#[path = "support/process_harness.rs"]
mod process_harness;
use process_harness::{Refusal, serving_config_document};

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inspection::MAX_HEADER_LINES;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::runtime::ServeStorage;

const LOOPS: usize = 64;
const OVERLONG_LOOPS: usize = 4;
const SETTLE_TURNS: usize = 20;
const BODY_403: &str = "403 Forbidden";
const BODY_400: &str = "400 Bad Request";
const NON_ALLOWLISTED_CONNECT: &[u8] = b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n";

fn rlimit_stack_readable() -> Option<String> {
    let contents = std::fs::read_to_string("/proc/self/limits").ok()?;
    contents
        .lines()
        .find(|l| l.contains("Max stack size"))
        .map(|l| l.trim().to_string())
}

fn main() {
    report_stack_limit();
    let (port, mut runtime) = boot_serving_runtime();
    refuse_non_allowlisted_connects(&mut runtime, port);
    refuse_overlong_heads(&mut runtime, port);
    println!(
        "MAIN-THREAD-STACK-OK loops={LOOPS} accept+reset cycles on true main thread; over-long-head refusals={OVERLONG_LOOPS}"
    );
}

fn report_stack_limit() {
    match rlimit_stack_readable() {
        Some(line) => println!("RLIMIT_STACK {line}"),
        None => println!("RLIMIT_STACK (not readable on this platform)"),
    }
}

fn boot_serving_runtime() -> (u16, Runtime) {
    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let config = parse_config_document(&serving_config_document(port)).expect("valid config");
    #[cfg(feature = "alloc-witness")]
    actual_attach_registration_failure_on_main(&config);
    let storage = ServeStorage::boot(&config).expect("boot storage");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let runtime = Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime");
    (port, runtime)
}

fn refuse_non_allowlisted_connects(runtime: &mut Runtime, port: u16) {
    for i in 0..LOOPS {
        Refusal {
            head: NON_ALLOWLISTED_CONNECT,
            expected_body: BODY_403,
            settle_turns: SETTLE_TURNS,
            failure: &format!(
                "iteration {i}: the server must refuse a non-allowlisted CONNECT with the 403 body"
            ),
        }
        .drive(runtime, port);
    }
}

fn overlong_connect_head() -> Vec<u8> {
    let mut head = Vec::with_capacity(64 + (MAX_HEADER_LINES + 1) * 10);
    head.extend_from_slice(b"CONNECT sub.example.org:443 HTTP/1.1\r\n");
    for _ in 0..MAX_HEADER_LINES + 1 {
        head.extend_from_slice(b"X-Hdr: v\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

fn refuse_overlong_heads(runtime: &mut Runtime, port: u16) {
    for i in 0..OVERLONG_LOOPS {
        let head = overlong_connect_head();
        Refusal {
            head: &head,
            expected_body: BODY_400,
            settle_turns: SETTLE_TURNS,
            failure: &format!(
                "over-long iteration {i}: a CONNECT head with more than {MAX_HEADER_LINES} header \
                 lines must be refused with the 400 body"
            ),
        }
        .drive(runtime, port);
    }
}

#[cfg(feature = "alloc-witness")]
fn actual_attach_registration_failure_on_main(config: &alumina::config::Config) {
    use alumina::alloc::{Phase, run_phase};
    use alumina::runtime::{Preallocated, RuntimeBuildError, ServeError};

    let storage = ServeStorage::boot(config).expect("boot failure-probe storage");
    let traffic = TrafficStorage::allocate().expect("boot failure-probe traffic");
    let owner =
        Preallocated::preallocate(storage, traffic).expect("preallocate failure-probe owner");
    let mut listener =
        MioListener::bind("127.0.0.1:0".parse().unwrap()).expect("bind probe listener");
    owner
        .serving()
        .registry()
        .register(&mut listener, mio::Token(9000), mio::Interest::READABLE)
        .expect("register once");
    let (control, baseline) = run_phase(Phase::Serving, || {
        owner
            .serving()
            .registry()
            .register(&mut listener, mio::Token(9000), mio::Interest::READABLE)
            .map_err(ServeError::from)
    });
    assert!(
        format!("{:?}", control.unwrap_err()).contains("AlreadyExists"),
        "control registration must fail because it is already registered"
    );
    let (result, counts) = run_phase(Phase::Serving, || owner.attach(listener));
    let error = match &result {
        Err(RuntimeBuildError::Attach(error)) => error,
        Err(error) => panic!("unexpected failure: {error:?}"),
        Ok(_) => panic!("duplicate registration unexpectedly succeeded"),
    };
    assert!(
        format!("{error:?}").contains("AlreadyExists"),
        "attachment must preserve the duplicate-registration failure"
    );
    assert_eq!(
        counts, baseline,
        "attachment added heap activity beyond the same Mio failure"
    );
    println!("MAIN-ATTACH-RETAINED-OK control={baseline:?} attach={counts:?}");
}
