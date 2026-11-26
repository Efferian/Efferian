use std::io;
use std::mem::MaybeUninit;
use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::signal::unix::{SignalKind, signal};

use crate::{MonoInstant, MonotonicClock, PlatformError};

/// Leader state at the final non-reaping observation before group escalation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminateOutcome {
    AlreadyCleaned,
    LeaderExitedBeforeKill,
    LeaderPendingAtKill,
}

#[derive(Debug)]
enum Cleanup {
    Waiting,
    TermSent(Duration),
    Grace {
        started: MonoInstant,
        duration: Duration,
    },
    Escalating,
    KillLeader,
    Reaping(TerminateOutcome),
    Cleaned(ExitStatus),
    LostChild,
}

/// Owns an isolated POSIX process group through cleanup and leader collection.
///
/// Keep the handle until cleanup succeeds, and service any extracted pipes
/// separately. Other code must leave collection of the leader to this handle.
/// Cleanup covers signalable members of the original group while Node is alive.
#[derive(Debug)]
pub struct ProcessHandle {
    child: Child,
    pid: libc::pid_t,
    cleanup: Cleanup,
}

impl ProcessHandle {
    pub fn spawn_isolated_group(cmd: &mut Command) -> Result<Self, PlatformError> {
        let mut child = cmd
            .process_group(0)
            .kill_on_drop(false)
            .spawn()
            .map_err(|error| PlatformError::process_io("spawn_process_group", error))?;
        let id = child.id().unwrap_or(0);
        let Some(pid) = libc::pid_t::try_from(id).ok().filter(|&pid| pid > 1) else {
            let _ = child.start_kill();
            return Err(PlatformError::InvalidProcessGroup { pid: id });
        };
        Ok(Self {
            child,
            pid,
            cleanup: Cleanup::Waiting,
        })
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// Wait for the leader, clean up its original group, and return its status.
    ///
    /// Dropping the pending future leaves the handle available for later cleanup.
    pub async fn wait_and_cleanup(&mut self) -> Result<ExitStatus, PlatformError> {
        self.child.stdin.take();
        if matches!(self.cleanup, Cleanup::Waiting) {
            let mut exits = signal(SignalKind::child())
                .map_err(|error| PlatformError::process_io("subscribe_child_exit", error))?;
            // Subscribe before the first probe so an exit between probing and
            // awaiting the signal still wakes this method.
            while !self.leader_exited()? {
                if exits.recv().await.is_none() {
                    return Err(PlatformError::process_io(
                        "receive_child_exit",
                        io::ErrorKind::BrokenPipe.into(),
                    ));
                }
            }
            self.cleanup = Cleanup::Escalating;
        }
        let (status, _) = self.finish_cleanup().await?;
        Ok(status)
    }

    /// Send TERM, give the group the full grace period, then escalate and reap.
    ///
    /// A zero grace period escalates immediately. The deadline bounds the time
    /// until escalation. Collecting the leader may take longer. An interrupted
    /// call resumes its recorded phase and deadline on the next cleanup call.
    pub async fn terminate_group(
        &mut self,
        grace: Duration,
    ) -> Result<TerminateOutcome, PlatformError> {
        self.child.stdin.take();
        if matches!(self.cleanup, Cleanup::Waiting) {
            self.cleanup = if grace.is_zero() {
                Cleanup::Escalating
            } else {
                self.leader_exited()?;
                self.signal_group(libc::SIGTERM)?;
                Cleanup::TermSent(grace)
            };
        }
        let (_, outcome) = self.finish_cleanup().await?;
        Ok(outcome)
    }

    async fn finish_cleanup(&mut self) -> Result<(ExitStatus, TerminateOutcome), PlatformError> {
        if let Cleanup::TermSent(grace) = self.cleanup {
            self.cleanup = Cleanup::Grace {
                started: MonotonicClock::now()?,
                duration: grace,
            };
        }
        if let Cleanup::Grace { started, duration } = self.cleanup {
            loop {
                let remaining = duration.saturating_sub(started.elapsed()?);
                if remaining.is_zero() {
                    break;
                }
                // Tokio's clock may pause during system suspend. Bound each
                // sleep so an expired suspend-aware deadline is noticed after resume.
                tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
            }
            self.cleanup = Cleanup::Escalating;
        }
        if matches!(self.cleanup, Cleanup::Escalating) {
            let exited = self.leader_exited()?;
            self.signal_group(libc::SIGKILL)?;
            self.cleanup = if exited {
                Cleanup::Reaping(TerminateOutcome::LeaderExitedBeforeKill)
            } else {
                Cleanup::KillLeader
            };
        }
        if matches!(self.cleanup, Cleanup::KillLeader) {
            // The direct child is still our responsibility even if it moved.
            if !self.leader_exited()? {
                self.child
                    .start_kill()
                    .map_err(|error| PlatformError::process_io("kill_process_leader", error))?;
            }
            self.cleanup = Cleanup::Reaping(TerminateOutcome::LeaderPendingAtKill);
        }
        match self.cleanup {
            Cleanup::Reaping(outcome) => {
                let status = self
                    .child
                    .wait()
                    .await
                    .map_err(|error| PlatformError::process_io("reap_process_leader", error))?;
                self.cleanup = Cleanup::Cleaned(status);
                Ok((status, outcome))
            }
            Cleanup::Cleaned(status) => Ok((status, TerminateOutcome::AlreadyCleaned)),
            Cleanup::LostChild => Err(PlatformError::process_io(
                "observe_process_leader",
                io::Error::from_raw_os_error(libc::ECHILD),
            )),
            _ => Err(PlatformError::process_io(
                "finish_process_cleanup",
                io::Error::other("cleanup was never started"),
            )),
        }
    }

    fn signal_group(&self, signal: libc::c_int) -> Result<(), PlatformError> {
        // SAFETY: pid > 1, so -pid addresses only the original process group.
        // The preceding WNOWAIT probe confirmed our unreaped child pins the
        // group ID. Callers pass only SIGTERM or SIGKILL.
        if unsafe { libc::kill(-self.pid, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(PlatformError::process_io("signal_process_group", error))
    }

    fn leader_exited(&mut self) -> Result<bool, PlatformError> {
        loop {
            let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: info is aligned writable storage. A zeroed siginfo_t
            // allows a zero PID even on systems that leave it untouched when
            // no exit is ready. A successful waitid supplies SIGCHLD data
            // when the child has exited. WNOWAIT leaves the child unreaped.
            let exited = unsafe {
                let result = libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                );
                (result == 0).then(|| info.assume_init().si_pid() != 0)
            };
            if let Some(exited) = exited {
                return Ok(exited);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.cleanup = Cleanup::LostChild;
            }
            return Err(PlatformError::process_io("observe_process_leader", error));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn losing_wait_ownership_disables_group_signaling() -> Result<(), PlatformError> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let mut handle = ProcessHandle::spawn_isolated_group(&mut command)?;
        handle
            .child
            .wait()
            .await
            .map_err(|error| PlatformError::process_io("test_reap", error))?;

        assert!(matches!(
            handle.terminate_group(Duration::ZERO).await,
            Err(PlatformError::Io { operation: "observe_process_leader", source, .. })
                if source.raw_os_error() == Some(libc::ECHILD)
        ));
        assert!(matches!(handle.cleanup, Cleanup::LostChild));
        assert!(handle.wait_and_cleanup().await.is_err());
        Ok(())
    }
}
