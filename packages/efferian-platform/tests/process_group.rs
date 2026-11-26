mod support;

use std::error::Error;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use efferian_platform::{ProcessHandle, TerminateOutcome};
use support::TestDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;
const OUTER_TIMEOUT: Duration = Duration::from_secs(5);
const GRACE: Duration = Duration::from_millis(400);

const COOPERATIVE_WORKER: &str = r#"
finish() {
    while [ ! -f leader-term ]; do sleep 0.01 >/dev/null; done
    sleep 0.12 >/dev/null
    printf 'finished\n'
    exit 0
}
trap finish TERM
"#;

const TERM_REPORTING_WORKER: &str = r#"trap 'printf "term\n"' TERM"#;
const TERM_IGNORING_WORKER: &str = "trap '' TERM";
const TERM_HANDLING_LEADER: &str = r#"trap ': > leader-term; exit 23' TERM"#;
const TERM_IGNORING_LEADER: &str = "trap '' TERM";

struct RunningGroup {
    handle: ProcessHandle,
    input: ChildStdin,
    worker_output: BufReader<ChildStdout>,
    _dir: TestDir,
}

impl RunningGroup {
    async fn start(leader_setup: &str, worker_setup: &str) -> Result<Self, Box<dyn Error>> {
        let dir = TestDir::new()?;
        // fd 3 moves stdout to the worker. The leader closes its copy
        // before authorizing readiness. All sleep commands discard stdout.
        // The worker alone holds the pipe's write end after readiness.
        let script = format!(
            r#"
{leader_setup}
exec 3>&1 1>&-
(
    exec 1>&3 3>&-
    {worker_setup}
    while [ ! -f leader-ready ]; do sleep 0.01 >/dev/null; done
    printf 'ready\n'
    ticks=0
    while [ "$ticks" -lt 200 ]; do
        sleep 0.05 >/dev/null
        ticks=$((ticks + 1))
    done
) &
exec 3>&-
: > leader-ready
IFS= read -r stop || :
exit 7
"#
        );
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", &script])
            .current_dir(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut handle = ProcessHandle::spawn_isolated_group(&mut command)?;
        let input = handle.take_stdin().ok_or("leader stdin was not piped")?;
        let stdout = handle.take_stdout().ok_or("worker stdout was not piped")?;
        assert!(handle.take_stdin().is_none());
        assert!(handle.take_stdout().is_none());
        assert!(handle.take_stderr().is_none());
        let mut group = Self {
            handle,
            input,
            worker_output: BufReader::new(stdout),
            _dir: dir,
        };
        assert_eq!(group.line().await?, "ready\n");
        Ok(group)
    }

    async fn line(&mut self) -> Result<String, Box<dyn Error>> {
        let mut line = String::new();
        timeout(OUTER_TIMEOUT, self.worker_output.read_line(&mut line)).await??;
        Ok(line)
    }

    async fn drain_until_eof(&mut self) -> Result<String, Box<dyn Error>> {
        let mut bytes = String::new();
        timeout(OUTER_TIMEOUT, self.worker_output.read_to_string(&mut bytes)).await??;
        Ok(bytes)
    }

    async fn wait(&mut self) -> Result<ExitStatus, Box<dyn Error>> {
        Ok(timeout(OUTER_TIMEOUT, self.handle.wait_and_cleanup()).await??)
    }

    async fn terminate(&mut self, grace: Duration) -> Result<TerminateOutcome, Box<dyn Error>> {
        Ok(timeout(OUTER_TIMEOUT, self.handle.terminate_group(grace)).await??)
    }
}

#[tokio::test]
async fn normal_leader_exit_cleans_up_a_live_worker_before_reap() -> TestResult {
    let mut group = RunningGroup::start(TERM_HANDLING_LEADER, TERM_IGNORING_WORKER).await?;
    group.input.write_all(b"exit\n").await?;
    let status = group.wait().await?;
    assert_eq!(status.code(), Some(7));
    assert_eq!(group.drain_until_eof().await?, "");
    assert_eq!(group.wait().await?, status);
    assert_eq!(
        group.terminate(GRACE).await?,
        TerminateOutcome::AlreadyCleaned
    );
    Ok(())
}

#[tokio::test]
async fn early_leader_exit_leaves_the_full_grace_for_a_cooperative_worker() -> TestResult {
    let mut group = RunningGroup::start(TERM_HANDLING_LEADER, COOPERATIVE_WORKER).await?;
    let start = Instant::now();
    assert_eq!(
        group.terminate(GRACE).await?,
        TerminateOutcome::LeaderExitedBeforeKill
    );
    assert!(start.elapsed() >= GRACE);
    assert_eq!(group.wait().await?.code(), Some(23));
    assert_eq!(group.drain_until_eof().await?, "finished\n");
    Ok(())
}

#[tokio::test]
async fn term_ignoring_group_is_killed_at_the_deadline() -> TestResult {
    let mut group = RunningGroup::start(TERM_IGNORING_LEADER, TERM_IGNORING_WORKER).await?;
    let start = Instant::now();
    assert_eq!(
        group.terminate(GRACE).await?,
        TerminateOutcome::LeaderPendingAtKill
    );
    assert!(start.elapsed() >= GRACE);
    assert_eq!(group.wait().await?.signal(), Some(libc::SIGKILL));
    assert_eq!(group.drain_until_eof().await?, "");
    Ok(())
}

#[tokio::test]
async fn cancelled_wait_remains_usable_and_zero_grace_skips_term() -> TestResult {
    let mut group = RunningGroup::start(TERM_HANDLING_LEADER, TERM_REPORTING_WORKER).await?;
    assert!(
        timeout(Duration::from_millis(30), group.handle.wait_and_cleanup())
            .await
            .is_err()
    );
    assert_eq!(
        group.terminate(Duration::ZERO).await?,
        TerminateOutcome::LeaderPendingAtKill
    );
    assert_eq!(group.wait().await?.signal(), Some(libc::SIGKILL));
    assert_eq!(group.drain_until_eof().await?, "");
    Ok(())
}

#[tokio::test]
async fn interrupted_grace_can_resume_with_either_cleanup_method() -> TestResult {
    for resume_by_wait in [true, false] {
        let mut group = RunningGroup::start(TERM_HANDLING_LEADER, TERM_REPORTING_WORKER).await?;
        let start = Instant::now();
        assert!(
            timeout(
                Duration::from_millis(50),
                group.handle.terminate_group(GRACE)
            )
            .await
            .is_err()
        );
        assert_eq!(group.line().await?, "term\n");

        if resume_by_wait {
            assert_eq!(group.wait().await?.code(), Some(23));
        } else {
            assert_eq!(
                group.terminate(Duration::from_secs(60)).await?,
                TerminateOutcome::LeaderExitedBeforeKill
            );
            assert_eq!(group.wait().await?.code(), Some(23));
        }

        assert!(start.elapsed() >= GRACE);
        assert_eq!(group.drain_until_eof().await?, "");
        assert_eq!(
            group.terminate(Duration::ZERO).await?,
            TerminateOutcome::AlreadyCleaned
        );
    }
    Ok(())
}

#[tokio::test]
async fn unclaimed_piped_stdin_is_closed_when_waiting() -> TestResult {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "IFS= read -r line || exit 11"])
        .stdin(Stdio::piped());
    let mut handle = ProcessHandle::spawn_isolated_group(&mut command)?;
    assert_eq!(
        timeout(OUTER_TIMEOUT, handle.wait_and_cleanup())
            .await??
            .code(),
        Some(11)
    );
    Ok(())
}

#[tokio::test]
async fn spawn_failure_is_returned_without_a_handle() -> TestResult {
    let dir = TestDir::new()?;
    let mut command = Command::new(dir.path().join("missing-command"));
    assert!(matches!(
        ProcessHandle::spawn_isolated_group(&mut command),
        Err(efferian_platform::PlatformError::Io { operation: "spawn_process_group", source, .. })
            if source.kind() == io::ErrorKind::NotFound
    ));
    Ok(())
}
