#[path = "support/process_harness.rs"]
mod process_harness;
use process_harness::{
    Refusal, boot_serving_runtime, run_child_or_parent, spawn_piped_child, wait_for_success,
};

use std::time::Duration;

use alumina::runtime::Runtime;

const STALL_TIMEOUT: Duration = Duration::from_secs(120);
const LOOPS: usize = 2000;
const SETTLE_TURNS: usize = 4;

fn main() {
    run_child_or_parent(parent_main, child_main);
}

/// Spawns the child with a piped stdout that is never read, so the pipe fills,
/// the child's nonblocking sink drops whole records, and the child must still
/// keep refusing connections. The parent waits for a clean exit within a
/// bounded timeout, killing and reaping the child on timeout.
fn parent_main() {
    let mut child = spawn_piped_child();
    wait_for_success(&mut child, STALL_TIMEOUT, "stdout stall");
}

fn child_main() {
    let (port, mut runtime) = boot_serving_runtime();
    let loops = refuse_while_stdout_unconsumed(&mut runtime, port);
    assert_bounded_drops(&runtime, loops);
}

fn refuse_while_stdout_unconsumed(runtime: &mut Runtime, port: u16) -> usize {
    for i in 0..LOOPS {
        Refusal::non_allowlisted_connect(
            SETTLE_TURNS,
            &format!(
                "iteration {i}: the server must still refuse with 403 while stdout is unconsumed"
            ),
        )
        .drive(runtime, port);
    }
    LOOPS
}

fn assert_bounded_drops(runtime: &Runtime, loops: usize) {
    let total_emitted = loops as u64;
    let dropped = runtime.serving().storage().log_dropped();
    assert!(
        dropped > 0,
        "the stall must actually fill the pipe and drop whole records: {dropped}"
    );
    assert!(
        dropped <= total_emitted,
        "drops are whole-record and never exceed the records emitted this run: {dropped}"
    );
    eprintln!(
        "STDOUT-STALL-OK loops={loops} refused-served-while-stalled=yes drops={dropped} (<= {total_emitted})"
    );
}
