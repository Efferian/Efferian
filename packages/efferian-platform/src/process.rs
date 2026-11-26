use std::io;
use std::mem::MaybeUninit;
use std::process::{Child, ExitStatus};
use std::time::Duration;

use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::signal::unix::{Signal, SignalKind, signal};

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
/// Keep the handle until cleanup succeeds. Take every piped stdout and stderr
/// and drain them concurrently with waiting, so the child can finish writing.
/// Use inherited or null output for streams the caller does not need to read.
/// Other code must leave collection of the leader to this handle.
/// Cleanup covers signalable members of the original group while Node is alive.
///
/// Spawn on a thread with SIGCHLD unblocked in a Tokio runtime with its I/O
/// and time drivers enabled. Keep SIGCHLD deliverable to the process and leave
/// its handler and leader collection under runtime and handle ownership.
#[derive(Debug)]
#[must_use = "retain the handle until the process group has been cleaned up"]
pub struct ProcessHandle {
    child: Child,
    exits: Signal,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    pid: libc::pid_t,
    cleanup: Cleanup,
}

impl ProcessHandle {
    /// Spawn the command as the leader of a new POSIX process group.
    ///
    /// # Panics
    ///
    /// May panic outside a Tokio runtime with an enabled I/O driver.
    pub fn spawn_isolated_group(cmd: &mut Command) -> Result<Self, PlatformError> {
        Self::spawn_with_registration(cmd, Self::register_pipes)
    }

    fn spawn_with_registration(
        cmd: &mut Command,
        register: impl FnOnce(&mut Self) -> io::Result<()>,
    ) -> Result<Self, PlatformError> {
        let exits = signal(SignalKind::child())
            .map_err(|error| PlatformError::process_io("subscribe_child_exit", error))?;
        check_child_signal_environment()
            .map_err(|error| PlatformError::process_io("check_child_signal", error))?;
        let mut child = cmd
            .process_group(0)
            .as_std_mut()
            .spawn()
            .map_err(|error| PlatformError::process_io("spawn_process_group", error))?;
        let id = child.id();
        let Some(pid) = libc::pid_t::try_from(id).ok().filter(|&pid| pid > 1) else {
            child
                .kill()
                .and_then(|()| child.wait())
                .map_err(|error| PlatformError::process_io("rollback_process_leader", error))?;
            return Err(PlatformError::InvalidProcessGroup { pid: id });
        };
        let mut handle = Self {
            child,
            pid,
            exits,
            stdin: None,
            stdout: None,
            stderr: None,
            cleanup: Cleanup::Waiting,
        };
        if let Err(error) = register(&mut handle) {
            // The kernel has already started the command. Keep ownership until
            // the group is signalled and the leader is collected on rollback.
            let exited = handle.leader_exited()?;
            let group = handle.signal_group(libc::SIGKILL);
            if !exited {
                handle
                    .child
                    .kill()
                    .map_err(|error| PlatformError::process_io("rollback_kill", error))?;
            }
            handle
                .child
                .wait()
                .map_err(|error| PlatformError::process_io("rollback_wait", error))?;
            group?;
            return Err(PlatformError::process_io(
                "register_process_pipes_after_spawn",
                error,
            ));
        }
        Ok(handle)
    }

    fn register_pipes(&mut self) -> io::Result<()> {
        self.stdin = self
            .child
            .stdin
            .take()
            .map(ChildStdin::from_std)
            .transpose()?;
        self.stdout = self
            .child
            .stdout
            .take()
            .map(ChildStdout::from_std)
            .transpose()?;
        self.stderr = self
            .child
            .stderr
            .take()
            .map(ChildStderr::from_std)
            .transpose()?;
        Ok(())
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.stderr.take()
    }

    /// Wait for the leader, clean up its original group, and return its status.
    ///
    /// Dropping the pending future leaves the handle available for later cleanup.
    ///
    /// # Panics
    ///
    /// May panic outside a Tokio runtime with I/O enabled. Resuming an
    /// interrupted grace period also requires the time driver.
    pub async fn wait_and_cleanup(&mut self) -> Result<ExitStatus, PlatformError> {
        self.stdin.take();
        if matches!(self.cleanup, Cleanup::Waiting) {
            self.observe_exit().await?;
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
    /// If reading the clock just after TERM fails, the call reports the error
    /// and a retry uses the timestamp taken immediately before the signal.
    ///
    /// # Panics
    ///
    /// May panic without an enabled Tokio time driver when waiting out a
    /// grace period. The TERM signal can already have been sent.
    pub async fn terminate_group(
        &mut self,
        grace: Duration,
    ) -> Result<TerminateOutcome, PlatformError> {
        self.stdin.take();
        if matches!(self.cleanup, Cleanup::Waiting) {
            if grace.is_zero() {
                self.cleanup = Cleanup::Escalating;
            } else {
                self.begin_grace(grace, MonotonicClock::now)?;
            }
        }
        let (_, outcome) = self.finish_cleanup().await?;
        Ok(outcome)
    }

    fn begin_grace(
        &mut self,
        duration: Duration,
        mut now: impl FnMut() -> Result<MonoInstant, PlatformError>,
    ) -> Result<(), PlatformError> {
        self.leader_exited()?;
        let before_term = now()?;
        self.signal_group(libc::SIGTERM)?;
        // Prefer the post-signal sample to give the group its full window.
        // If the clock fails here, retries can still use the pre-signal sample.
        let after_term = now();
        self.cleanup = Cleanup::Grace {
            started: after_term.as_ref().copied().unwrap_or(before_term),
            duration,
        };
        after_term.map(|_| ())
    }

    async fn finish_cleanup(&mut self) -> Result<(ExitStatus, TerminateOutcome), PlatformError> {
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
                    .kill()
                    .map_err(|error| PlatformError::process_io("kill_process_leader", error))?;
            }
            self.cleanup = Cleanup::Reaping(TerminateOutcome::LeaderPendingAtKill);
        }
        match self.cleanup {
            Cleanup::Reaping(outcome) => {
                self.observe_exit().await?;
                let status = self
                    .child
                    .wait()
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

    async fn observe_exit(&mut self) -> Result<(), PlatformError> {
        while !self.leader_exited()? {
            if self.exits.recv().await.is_none() {
                return Err(PlatformError::process_io(
                    "receive_child_exit",
                    io::ErrorKind::BrokenPipe.into(),
                ));
            }
        }
        Ok(())
    }

    fn signal_group(&mut self, signal: libc::c_int) -> Result<(), PlatformError> {
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
        // XNU excludes zombies from group-signal recipients. A group whose
        // only remaining member is its unreaped leader can report EPERM.
        #[cfg(target_os = "macos")]
        if error.raw_os_error() == Some(libc::EPERM) && self.leader_exited()? {
            return Ok(());
        }
        Err(PlatformError::process_io("signal_process_group", error))
    }

    fn leader_exited(&mut self) -> Result<bool, PlatformError> {
        loop {
            let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: info is aligned writable storage. A zeroed siginfo_t
            // allows a zero PID even on systems that leave it untouched when
            // no event is ready. A successful waitid supplies SIGCHLD data
            // for a ready event. WNOWAIT leaves the child unreaped.
            let event = unsafe {
                let result = libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                );
                (result == 0).then(|| {
                    let info = info.assume_init();
                    (info.si_pid(), info.si_code)
                })
            };
            if let Some((pid, code)) = event {
                return Ok(pid == self.pid && is_exit_event(code));
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

fn check_child_signal_environment() -> io::Result<()> {
    let mut mask = MaybeUninit::<libc::sigset_t>::uninit();
    let mut action = MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: null input pointers query the current mask and disposition. The
    // output storage is aligned and only inspected after the call succeeds.
    unsafe {
        let err = libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), mask.as_mut_ptr());
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err));
        }
        if libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        // Some libcs only initialize the kernel-sized part of sa_mask. Read
        // the two reported fields without constructing the whole sigaction.
        let flags = (*action.as_ptr()).sa_flags;
        let handler = (*action.as_ptr()).sa_sigaction;
        if libc::sigismember(mask.as_ptr(), libc::SIGCHLD) != 0
            || flags & libc::SA_NOCLDWAIT != 0
            || matches!(handler, libc::SIG_IGN | libc::SIG_DFL)
        {
            return Err(io::Error::other(
                "SIGCHLD must be deliverable and child status retained",
            ));
        }
    }
    Ok(())
}

fn is_exit_event(code: libc::c_int) -> bool {
    // Linux can report a ptrace stop even when waitid requests only WEXITED.
    matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clock_failure_does_not_restart_a_term_window() -> Result<(), PlatformError> {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("2");
        let mut handle = ProcessHandle::spawn_isolated_group(&mut cmd)?;
        let grace = Duration::from_millis(10);
        assert!(
            handle
                .begin_grace(grace, || Err(PlatformError::ClockOverflow))
                .is_err()
        );
        assert!(matches!(handle.cleanup, Cleanup::Waiting));

        let before = MonotonicClock::now()?;
        let mut sample = Some(before);
        assert!(matches!(
            handle.begin_grace(grace, || sample.take().ok_or(PlatformError::ClockOverflow)),
            Err(PlatformError::ClockOverflow)
        ));
        assert!(
            matches!(handle.cleanup, Cleanup::Grace { started, duration }
            if started == before && duration == grace)
        );
        handle.wait_and_cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn termination_collects_an_exited_solitary_leader() -> Result<(), PlatformError> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 23"]);
        let mut handle = ProcessHandle::spawn_isolated_group(&mut command)?;
        handle.observe_exit().await?;
        assert_eq!(
            handle.terminate_group(Duration::from_millis(1)).await?,
            TerminateOutcome::LeaderExitedBeforeKill
        );
        assert_eq!(handle.wait_and_cleanup().await?.code(), Some(23));
        Ok(())
    }

    #[tokio::test]
    async fn failed_registration_cleans_up_the_spawned_group()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read;
        use std::process::Stdio;
        use tokio::io::AsyncReadExt;

        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30 & printf x; wait"])
            .stdout(Stdio::piped());
        cmd.kill_on_drop(true);
        let mut pipe = None;
        let error = ProcessHandle::spawn_with_registration(&mut cmd, |handle| {
            let mut out = handle
                .child
                .stdout
                .take()
                .ok_or(io::Error::other("missing pipe"))?;
            // The worker already inherited the write end when the leader prints x.
            let mut ready = [0];
            out.read_exact(&mut ready)?;
            assert_eq!(ready, [b'x']);
            pipe = Some(ChildStdout::from_std(out)?);
            Err(io::Error::other("injected registration failure"))
        });
        assert!(matches!(
            error,
            Err(PlatformError::Io {
                operation: "register_process_pipes_after_spawn",
                ..
            })
        ));
        assert!(cmd.get_kill_on_drop());
        let mut pipe = pipe.ok_or("missing worker pipe")?;
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), pipe.read_to_end(&mut output)).await??;
        assert!(output.is_empty());
        Ok(())
    }

    #[test]
    fn blocked_sigchld_is_reported_before_spawn() -> Result<(), Box<dyn std::error::Error>> {
        // A dedicated test thread owns its signal mask until it exits.
        std::thread::spawn(|| -> io::Result<()> {
            let mut mask = MaybeUninit::<libc::sigset_t>::uninit();
            // SAFETY: sigemptyset initializes the mask used by the next two calls.
            // pthread_sigmask changes only this test thread and retains no pointer.
            unsafe {
                if libc::sigemptyset(mask.as_mut_ptr()) != 0
                    || libc::sigaddset(mask.as_mut_ptr(), libc::SIGCHLD) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                let error =
                    libc::pthread_sigmask(libc::SIG_BLOCK, mask.as_ptr(), std::ptr::null_mut());
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(error));
                }
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let _entered = runtime.enter();
            let result = ProcessHandle::spawn_isolated_group(&mut Command::new("/bin/true"));
            assert!(matches!(
                result,
                Err(PlatformError::Io {
                    operation: "check_child_signal",
                    ..
                })
            ));
            Ok(())
        })
        .join()
        .map_err(|_| "test thread failed")??;
        Ok(())
    }

    #[test]
    fn only_exit_events_indicate_leader_completion() {
        for code in [libc::CLD_EXITED, libc::CLD_KILLED, libc::CLD_DUMPED] {
            assert!(is_exit_event(code));
        }
        for code in [0, libc::CLD_TRAPPED, libc::CLD_STOPPED, libc::CLD_CONTINUED] {
            assert!(!is_exit_event(code));
        }
    }

    #[tokio::test]
    async fn losing_wait_ownership_disables_group_signaling() -> Result<(), PlatformError> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let mut handle = ProcessHandle::spawn_isolated_group(&mut command)?;
        handle
            .child
            .wait()
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
