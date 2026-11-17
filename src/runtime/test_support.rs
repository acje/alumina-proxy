use std::collections::BTreeSet;
use std::net::TcpListener;
use std::sync::Mutex;

/// Ports already handed out in this process. Two tests that probe
/// `127.0.0.1:0`, drop the probe and bind later can be handed the same port in
/// between, which surfaced as a spurious `AddrInUse`. Issuing
/// each port once, from this one process-wide set, removes that inter-test
/// collision across every runtime test module in the one libtest process. It
/// does not guard against a non-test process taking the port, so fixtures that
/// must connect prefer `Config::with_kernel_assigned_test_listener`.
static ISSUED_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

pub(crate) fn ephemeral_port() -> u16 {
    for _ in 0..64 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if ISSUED_PORTS.lock().expect("issued-port lock").insert(port) {
            return port;
        }
    }
    panic!("no unissued ephemeral port after 64 probes");
}
