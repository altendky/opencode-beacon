use std::{
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn signal_stops_monitor(signal: &str) {
    let child = Command::new(env!("CARGO_BIN_EXE_opencode-beacon"))
        .args(["--no-claude", "watch"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| unreachable!("monitor starts: {error}"));
    let mut child = ChildGuard(child);

    // Give the process time to install handlers and enter continuous monitoring.
    thread::sleep(Duration::from_millis(250));
    let status = Command::new("kill")
        .args([signal, &child.0.id().to_string()])
        .status()
        .unwrap_or_else(|error| unreachable!("kill command runs: {error}"));
    assert!(status.success());

    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .unwrap_or_else(|error| unreachable!("child status is available: {error}"))
        {
            assert!(status.success());
            return;
        }
        assert!(
            Instant::now() < deadline,
            "monitor did not stop after {signal}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn sigint_triggers_bounded_graceful_shutdown() {
    signal_stops_monitor("-INT");
}

#[test]
fn sigterm_triggers_bounded_graceful_shutdown() {
    signal_stops_monitor("-TERM");
}
