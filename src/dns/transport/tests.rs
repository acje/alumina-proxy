use super::*;

use crate::config::parse_config_document;

use crate::dns::schedule::{INCIDENT_N, INCIDENT_WINDOW};

use crate::dns::wire::classify_published;

use crate::enforcement::monitor::DnsAnomalyKind;

use std::io::{Read, Write};

use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};

use std::sync::{Arc, Mutex};

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use std::thread;

pub(crate) enum Step {
    PositiveA {
        ttl: u32,
        octets: [u8; 4],
    },
    PositiveAAd {
        ttl: u32,
        octets: [u8; 4],
    },
    PositiveAaaa {
        ttl: u32,
        octets: [u8; 16],
    },
    NodataWithSoa {
        ttl: u32,
        min: u32,
    },
    NxdomainWithSoa {
        ttl: u32,
        min: u32,
    },
    BailiwickViolationCname {
        ttl: u32,
    },
    PositiveAMismatchedTid {
        ttl: u32,
        octets: [u8; 4],
    },
    FragmentedPositive {
        ttl: u32,
        octets: [u8; 4],
        chunk: usize,
        gap: Duration,
    },
    Stall(Duration),
    Malformed(Vec<u8>),
    LengthPrefixOnly {
        len: u16,
    },
    Close,
}

pub(crate) struct Responder {
    addr: SocketAddr,
    handle: Option<thread::JoinHandle<()>>,
    connections: Arc<AtomicUsize>,
    closed_after_prefix: Arc<AtomicUsize>,
}

pub(crate) struct BoundedResponder {
    responder: Option<Responder>,
    cancel: Arc<ResponderCancellation>,
}

struct ResponderCancellation {
    requested: AtomicBool,
    active: Mutex<Option<TcpStream>>,
}

impl BoundedResponder {
    pub(crate) fn port(&self) -> u16 {
        self.responder.as_ref().unwrap().port()
    }

    pub(crate) fn finish(mut self) -> thread::Result<()> {
        self.cancel_and_join()
    }

    fn cancel_and_join(&mut self) -> thread::Result<()> {
        let Some(mut responder) = self.responder.take() else {
            return Ok(());
        };
        self.cancel.requested.store(true, Ordering::Release);
        let active = self
            .cancel
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(stream) = active.as_ref() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        drop(active);
        let Some(handle) = responder.handle.take() else {
            return Ok(());
        };
        handle.thread().unpark();
        handle.join()
    }
}

impl Drop for BoundedResponder {
    fn drop(&mut self) {
        let _ = self.cancel_and_join();
    }
}

impl Responder {
    pub(crate) fn port(&self) -> u16 {
        self.addr.port()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .expect("responder thread panicked; test result is unreliable");
        }
    }
}

fn qname_bytes(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).expect("dns label at most 63 bytes"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn soa_rdata(apex: &str, minimum: u32) -> Vec<u8> {
    let mut rd = qname_bytes(&format!("ns1.{apex}"));
    rd.extend_from_slice(&qname_bytes(&format!("hostmaster.{apex}")));
    for v in [1u32, 3600, 600, 86400, minimum] {
        rd.extend_from_slice(&v.to_be_bytes());
    }
    rd
}

fn question_from(query: &[u8]) -> Vec<u8> {
    query[12..].to_vec()
}

fn record(owner: &[u8], ty: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut rec = owner.to_vec();
    rec.extend_from_slice(&ty.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&ttl.to_be_bytes());
    rec.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("rdata fits u16 wire length")
            .to_be_bytes(),
    );
    rec.extend_from_slice(rdata);
    rec
}

/// The reply sections one scripted step contributes: the response code plus the
/// answer and authority records, whose counts the header derives.
struct AnswerSections {
    rcode: u16,
    answers: Vec<Vec<u8>>,
    authority: Vec<Vec<u8>>,
}

/// The SOA record a negative scripted step puts in the authority section.
fn soa_record(ttl: u32, min: u32) -> Vec<u8> {
    record(
        &qname_bytes("example.org"),
        6,
        ttl,
        &soa_rdata("example.org", min),
    )
}

/// Names the reply sections for one step, or `None` for the steps that answer
/// nothing on the wire (stall, close, malformed, length-prefix, fragmented).
fn answer_sections(qname: &[u8], step: &Step) -> Option<AnswerSections> {
    let sections = match step {
        Step::PositiveA { ttl, octets }
        | Step::PositiveAAd { ttl, octets }
        | Step::PositiveAMismatchedTid { ttl, octets } => AnswerSections {
            rcode: 0,
            answers: vec![record(qname, 1, *ttl, octets)],
            authority: Vec::new(),
        },
        Step::PositiveAaaa { ttl, octets } => AnswerSections {
            rcode: 0,
            answers: vec![record(qname, 28, *ttl, octets)],
            authority: Vec::new(),
        },
        Step::NodataWithSoa { ttl, min } => AnswerSections {
            rcode: 0,
            answers: Vec::new(),
            authority: vec![soa_record(*ttl, *min)],
        },
        Step::NxdomainWithSoa { ttl, min } => AnswerSections {
            rcode: 3,
            answers: Vec::new(),
            authority: vec![soa_record(*ttl, *min)],
        },
        Step::BailiwickViolationCname { ttl } => AnswerSections {
            rcode: 0,
            answers: vec![record(qname, 5, *ttl, &qname_bytes("evil.com"))],
            authority: Vec::new(),
        },
        Step::Stall(_)
        | Step::Malformed(_)
        | Step::LengthPrefixOnly { .. }
        | Step::FragmentedPositive { .. }
        | Step::Close => return None,
    };
    Some(sections)
}

/// Assembles one wire reply from `sections`, mirroring the request tid and
/// question and setting the authoritative bit for the AA step.
fn assemble_reply(tid: u16, step: &Step, question: &[u8], sections: AnswerSections) -> Vec<u8> {
    let flags = 0x8000
        | sections.rcode
        | if matches!(step, Step::PositiveAAd { .. }) {
            0x20
        } else {
            0
        };
    let mut msg = Vec::new();
    msg.extend_from_slice(&tid.to_be_bytes());
    msg.extend_from_slice(&flags.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    for count in [sections.answers.len(), sections.authority.len()] {
        msg.extend_from_slice(
            &u16::try_from(count)
                .expect("section count fits u16 wire length")
                .to_be_bytes(),
        );
    }
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(question);
    for rec in sections.answers.into_iter().chain(sections.authority) {
        msg.extend_from_slice(&rec);
    }
    msg
}

fn respond_for(query: &[u8], step: &Step) -> Option<Vec<u8>> {
    let sections = answer_sections(&query[12..query.len() - 4], step)?;
    let tid = u16::from_be_bytes([query[0], query[1]]);
    let question = question_from(query);
    Some(assemble_reply(tid, step, &question, sections))
}

fn wait_script_duration(duration: Duration, cancel: Option<&ResponderCancellation>) {
    let Some(cancel) = cancel else {
        thread::sleep(duration);
        return;
    };
    let deadline = Instant::now() + duration;
    while !cancel.requested.load(Ordering::Acquire) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::park_timeout(remaining);
    }
}

pub(crate) fn spawn_responder(conn_scripts: Vec<Vec<Step>>) -> Responder {
    spawn_responder_impl(conn_scripts, None)
}

pub(crate) fn spawn_bounded_responder(conn_scripts: Vec<Vec<Step>>) -> BoundedResponder {
    let cancel = Arc::new(ResponderCancellation {
        requested: AtomicBool::new(false),
        active: Mutex::new(None),
    });
    let responder = spawn_responder_impl(conn_scripts, Some(Arc::clone(&cancel)));
    BoundedResponder {
        responder: Some(responder),
        cancel,
    }
}

/// Binds the loopback listener the scripted responder accepts on, nonblocking
/// when a cancellation token must be observed between accepts.
fn bind_responder_listener(cancellable: bool) -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
    if cancellable {
        listener
            .set_nonblocking(true)
            .expect("nonblocking responder");
    }
    let addr = listener.local_addr().expect("responder addr");
    (listener, addr)
}

/// Accepts the next scripted connection, or `None` once cancellation is
/// requested or the listener reports a non-transient failure.
fn accept_scripted_connection(
    listener: &TcpListener,
    cancel: Option<&ResponderCancellation>,
) -> Option<(TcpStream, SocketAddr)> {
    loop {
        match listener.accept() {
            Ok(pair) => return Some(pair),
            Err(err) if cancel.is_some() && err.kind() == io::ErrorKind::WouldBlock => {
                if cancel.is_some_and(|state| state.requested.load(Ordering::Acquire)) {
                    return None;
                }
                thread::park_timeout(Duration::from_millis(50));
            }
            Err(err) if cancel.is_some() => panic!("responder accept failed: {err}"),
            Err(_) => return None,
        }
    }
}

/// Arms the accepted stream for scripted serving and records it as the stream
/// the cancellation token shuts down; `false` when cancellation won the race.
fn arm_active_stream(state: &ResponderCancellation, sock: &mut TcpStream) -> bool {
    let mut active = state.active.lock().unwrap();
    if state.requested.load(Ordering::Acquire) {
        return false;
    }
    sock.set_nonblocking(false).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    *active = Some(sock.try_clone().unwrap());
    true
}

/// Replays one scripted step on `sock`, reporting whether the connection may
/// take the next step.
fn run_scripted_step(
    sock: &mut TcpStream,
    step: &Step,
    cancel: Option<&ResponderCancellation>,
    closed_after_prefix: &AtomicUsize,
) -> bool {
    match step {
        Step::Stall(duration) => {
            wait_script_duration(*duration, cancel);
            true
        }
        Step::Close => false,
        Step::Malformed(bytes) => send_malformed(sock, bytes),
        Step::LengthPrefixOnly { len } => probe_length_prefix(sock, *len, closed_after_prefix),
        Step::FragmentedPositive {
            ttl,
            octets,
            chunk,
            gap,
        } => send_fragmented(sock, *ttl, *octets, *chunk, *gap, cancel),
        step => send_scripted_reply(sock, step),
    }
}

/// Replays one connection's script, stopping at the script end, at a step that
/// closes the connection, or when cancellation is requested.
fn serve_scripted_connection(
    sock: &mut TcpStream,
    steps: Vec<Step>,
    cancel: Option<&ResponderCancellation>,
    closed_after_prefix: &AtomicUsize,
) {
    for step in steps {
        if cancel.is_some_and(|state| state.requested.load(Ordering::Acquire)) {
            break;
        }
        if !run_scripted_step(sock, &step, cancel, closed_after_prefix) {
            break;
        }
    }
}

fn spawn_responder_impl(
    conn_scripts: Vec<Vec<Step>>,
    cancel: Option<Arc<ResponderCancellation>>,
) -> Responder {
    let (listener, addr) = bind_responder_listener(cancel.is_some());
    let connections = Arc::new(AtomicUsize::new(0));
    let connections_thread = Arc::clone(&connections);
    let closed_after_prefix = Arc::new(AtomicUsize::new(0));
    let closed_after_prefix_thread = Arc::clone(&closed_after_prefix);
    let handle = thread::spawn(move || {
        for conn_steps in conn_scripts {
            if cancel
                .as_ref()
                .is_some_and(|state| state.requested.load(Ordering::Acquire))
            {
                break;
            }
            let Some((mut sock, _)) = accept_scripted_connection(&listener, cancel.as_deref())
            else {
                break;
            };
            if let Some(state) = &cancel
                && !arm_active_stream(state, &mut sock)
            {
                break;
            }
            connections_thread.fetch_add(1, Ordering::Relaxed);
            serve_scripted_connection(
                &mut sock,
                conn_steps,
                cancel.as_deref(),
                &closed_after_prefix_thread,
            );
            if let Some(state) = &cancel {
                *state.active.lock().unwrap() = None;
            }
        }
    });
    Responder {
        addr,
        handle: Some(handle),
        connections,
        closed_after_prefix,
    }
}

fn send_scripted_reply(sock: &mut TcpStream, step: &Step) -> bool {
    let Some(q) = read_query(sock) else {
        return false;
    };
    let reply = respond_for(&q, step);
    if let Some(mut bytes) = reply {
        if matches!(step, Step::PositiveAMismatchedTid { .. }) {
            let mismatched = u16::from_be_bytes([bytes[0], bytes[1]]).wrapping_add(1);
            bytes[0] = (mismatched >> 8) as u8;
            bytes[1] = u8::try_from(mismatched & 0xff).expect("dns tid low byte");
        }
        let mut out = Vec::with_capacity(bytes.len() + 2);
        out.extend_from_slice(
            &u16::try_from(bytes.len())
                .expect("reply fits u16 wire length")
                .to_be_bytes(),
        );
        out.extend_from_slice(&bytes);
        if sock.write_all(&out).is_err() {
            return false;
        }
    }
    true
}

fn send_malformed(sock: &mut TcpStream, bytes: &[u8]) -> bool {
    let Some(_query) = read_query(sock) else {
        return false;
    };
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(
        &u16::try_from(bytes.len())
            .expect("reply fits u16 wire length")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    sock.write_all(&out).is_ok()
}

fn probe_length_prefix(sock: &mut TcpStream, len: u16, closed: &AtomicUsize) -> bool {
    let Some(_query) = read_query(sock) else {
        return false;
    };
    if sock.write_all(&len.to_be_bytes()).is_err() {
        return false;
    }
    let _ = sock.set_read_timeout(Some(Duration::from_millis(400)));
    let mut probe = [0u8; 1];
    if matches!(sock.read(&mut probe), Ok(0)) {
        closed.fetch_add(1, Ordering::Relaxed);
    }
    true
}

fn send_fragmented(
    sock: &mut TcpStream,
    ttl: u32,
    octets: [u8; 4],
    chunk: usize,
    gap: Duration,
    cancel: Option<&ResponderCancellation>,
) -> bool {
    let Some(q) = read_query(sock) else {
        return false;
    };
    let msg = positive_a_message(&q, ttl, octets);
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(
        &u16::try_from(msg.len())
            .expect("reply fits u16 wire length")
            .to_be_bytes(),
    );
    out.extend_from_slice(&msg);
    let mut at = 0;
    while at < out.len() {
        let take = (out.len() - at).min(chunk.max(1));
        if sock.write_all(&out[at..at + take]).is_err() {
            break;
        }
        at += take;
        if at < out.len() {
            wait_script_duration(gap, cancel);
        }
    }
    true
}

fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut lenb = [0u8; 2];
    if read_exact(sock, &mut lenb).is_err() {
        return None;
    }
    let qlen = usize::from(u16::from_be_bytes(lenb));
    let mut q = vec![0u8; qlen];
    if qlen == 0 || read_exact(sock, &mut q).is_err() {
        return None;
    }
    Some(q)
}

fn positive_a_message(q: &[u8], ttl: u32, octets: [u8; 4]) -> Vec<u8> {
    let tid = u16::from_be_bytes([q[0], q[1]]);
    let qname = &q[12..q.len() - 4];
    let mut msg = Vec::new();
    msg.extend_from_slice(&tid.to_be_bytes());
    msg.extend_from_slice(&0x8000u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&question_from(q));
    msg.extend_from_slice(&record(qname, 1, ttl, &octets));
    msg
}

fn read_exact(sock: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = sock.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        }
        filled += n;
    }
    Ok(())
}

fn config() -> Config {
    parse_config_document(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"beta.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n",
    )
    .expect("valid config")
}

fn ns(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)
}

fn bindings_of(
    cache: &Cache,
    ordinal: usize,
    family: Family,
) -> Vec<crate::eligibility::NumericAddr> {
    cache
        .entry(cache.name_index(ordinal).unwrap(), family)
        .unwrap()
        .bindings()
        .to_vec()
}

/// Drives one cooperative exchange on the transport through `wait_dns_readiness`
/// waits until it concludes, returning the terminal turn (never `Pending`).
fn run_exchange_to_terminal(
    transport: &mut StartupDns,
    fqdn: &crate::config::Fqdn,
    cache: &mut Cache,
    schedules: &mut Schedules,
    deadline: Instant,
) -> TurnResult {
    loop {
        match transport
            .advance_exchange(fqdn, cache, schedules)
            .expect("exchange turn")
        {
            TurnResult::Pending => {
                let _ = transport.wait_dns_readiness(deadline).expect("dns wait");
            }
            terminal => return terminal,
        }
    }
}

/// Starts one exchange with a fresh short deadline and drives it to its
/// terminal turn, asserting its terminal variant satisfies `expect`.
fn run_exchange_expecting(
    transport: &mut StartupDns,
    fqdn: &crate::config::Fqdn,
    cache: &mut Cache,
    schedules: &mut Schedules,
    expect: impl Fn(&TurnResult) -> bool,
) {
    // A fresh deadline per exchange keeps every exchange dialing: the
    // responder scripts rely on one accepted connection per exchange.
    let deadline = Instant::now() + Duration::from_millis(200);
    let name_index = cache.name_index(0).unwrap();
    let generation = cache
        .generations_before_query(name_index, Family::A)
        .unwrap();
    transport
        .start_exchange(
            fqdn,
            Family::A,
            0,
            deadline,
            generation,
            ExchangeClass::Startup,
        )
        .unwrap();
    let terminal = run_exchange_to_terminal(transport, fqdn, cache, schedules, deadline);
    assert!(
        expect(&terminal),
        "the exchange must conclude as expected, got {terminal:?}"
    );
}

/// The turn budget one scripted exchange is driven under: a scripted peer must
/// conclude well inside it, so an exhausted budget is a test failure, not a
/// tolerant pass.
const EXCHANGE_DRIVE_TURNS: usize = 256;

/// A startup case seated on a scripted responder that replays one positive-A
/// reply per connection: the first allowlist name and a fresh deadline travel
/// with the transport, cache and schedules the exchange drives.
struct ScriptedPositive {
    responder: Responder,
    transport: StartupDns,
    cache: Cache,
    schedules: Schedules,
    fqdn: Fqdn,
    deadline: Instant,
}

fn scripted_positive(ttl: u32, octets: [u8; 4]) -> ScriptedPositive {
    let responder = spawn_responder(vec![vec![
        Step::PositiveA { ttl, octets },
        Step::Close,
    ]]);
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    ScriptedPositive {
        responder,
        transport,
        cache: Cache::new(2).unwrap(),
        schedules: Schedules::new(2).unwrap(),
        fqdn: config().allowlist().get(0).unwrap().clone(),
        deadline: Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS),
    }
}

/// Starts the first exchange on `transport` for `fqdn` at the initial
/// generation, under the caller's class.
fn start_first_exchange(
    transport: &mut StartupDns,
    fqdn: &Fqdn,
    deadline: Instant,
    class: ExchangeClass,
) {
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL, class)
        .expect("first exchange starts");
}

/// Advances one exchange turn, returning the turn the transport reported so the
/// caller keeps deciding what that turn must be.
fn advance_turn(
    transport: &mut StartupDns,
    fqdn: &Fqdn,
    cache: &mut Cache,
    schedules: &mut Schedules,
) -> TurnResult {
    transport
        .advance_exchange(fqdn, cache, schedules)
        .expect("exchange turn")
}

/// Drives one exchange to its terminal turn under [`EXCHANGE_DRIVE_TURNS`],
/// waiting for the owner-owned readiness the turn asked for unless the exchange
/// deadline is already spent (waiting past it would block); `None` means the
/// budget ran out with the exchange still pending.
fn drive_exchange_to_terminal(
    transport: &mut StartupDns,
    fqdn: &Fqdn,
    cache: &mut Cache,
    schedules: &mut Schedules,
    deadline: Instant,
) -> Option<Result<TurnResult, StartupDnsError>> {
    for _ in 0..EXCHANGE_DRIVE_TURNS {
        match transport.advance_exchange(fqdn, cache, schedules) {
            Ok(TurnResult::Pending) => {
                if transport
                    .exchange_deadline()
                    .is_some_and(|d| Instant::now() >= d)
                {
                    continue;
                }
                let _ = transport.wait_dns_readiness(deadline).expect("dns wait");
            }
            terminal => return Some(terminal),
        }
    }
    None
}

/// Builds a configured resolver set from numeric address strings for the pure
/// failover/failback state-machine tests (loopback dialing is impossible:
/// `Nameserver` fixes the port at 53, and the relay would reach a real host).
fn resolver_set_of(addrs: &[&str]) -> ResolverSet {
    let mut entries = [crate::dns::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
    for (slot, addr) in addrs.iter().enumerate() {
        entries[slot] = crate::dns::resolver::select(addr).expect("ns");
    }
    ResolverSet::from_slice(&entries[..addrs.len()]).expect("resolver count fits")
}

/// A transport seated onto a configured resolver set with the primary active,
/// as [`StartupDns::begin_window`] leaves it: the primary is recorded as
/// exercised by the startup window.
fn seeded_transport(set: ResolverSet) -> StartupDns {
    let mut transport = StartupDns::new().unwrap();
    transport.resolvers = Some(set);
    transport.active_resolver = ActiveResolver::primary_of(&set);
    transport.window_exercised[0] = true;
    transport.now0 = 1_000_000;
    transport
}

/// Builds the in-flight exchange a `note_failure` call reads, with the
/// remaining fields as innocuous defaults for the direct-call tests.
fn fixture_exchange(ordinal: usize, family: Family, class: ExchangeClass) -> ActiveExchange {
    ActiveExchange {
        ordinal,
        family,
        deadline: Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS),
        step: ExchangeStep::Connecting,
        qlen: 2,
        connect_err: None,
        tid: 0,
        class,
        generation: Generation::INITIAL,
        other_generation: Generation::INITIAL,
        query_floor: 0,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "long two-arm serving-positive pipeline: the real advance loop and the open/relocation/recovery note assertions stay coherent across the configured and unconfigured arms"
)]
fn serving_positive_recovered_note_case(configured: bool) {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        },
        Step::Close,
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = if configured {
        seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8"]))
    } else {
        StartupDns::new().unwrap()
    };
    let expected_open = configured.then_some(0);
    let expected_actor = configured.then_some(1);
    transport
        .note_failure(
            &fixture_exchange(0, Family::A, ExchangeClass::Serving),
            &mut schedules,
            FailureReason::Connect,
        )
        .expect("open a serving A incident");
    assert_eq!(
        transport.take_incident_notes(),
        [
            Some(IncidentNote::Open {
                ordinal: 0,
                family: Family::A,
                reason: FailureReason::Connect,
                resolver: expected_open,
            }),
            None,
        ],
        "the open origin is the failing resolver, or None with no set, before any relocation"
    );
    for _ in 0..2 {
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Timeout,
            )
            .expect("advance the serving A incident toward degradation");
    }
    assert_eq!(
        transport.active_resolver.index(),
        if configured { 1 } else { 0 },
        "the third consecutive failure relocates onto the backup, or stays put with no set"
    );
    assert_eq!(
        transport.take_incident_notes(),
        [None, None],
        "the relocation failures stay silent while the incident is open"
    );
    transport.addr = ns(responder.port());
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
    transport
        .start_exchange(
            fqdn,
            Family::A,
            0,
            deadline,
            Generation::INITIAL,
            ExchangeClass::Serving,
        )
        .unwrap();
    let mut result = None;
    for _ in 0..256 {
        match transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap()
        {
            TurnResult::Pending => {
                if transport
                    .exchange_deadline()
                    .is_some_and(|d| Instant::now() >= d)
                {
                    continue;
                }
                let _ = transport.wait_dns_readiness(deadline).unwrap();
            }
            term => {
                result = Some(term);
                break;
            }
        }
    }
    assert!(
        matches!(result, Some(TurnResult::Published(_))),
        "a serving positive must publish, got {result:?}"
    );
    let notes = transport.take_incident_notes();
    let Some(IncidentNote::Recovered {
        ordinal: 0,
        family: Family::A,
        resolver,
        ..
    }) = notes[0]
    else {
        panic!("the recovery must be a serving A note, got {notes:?}");
    };
    assert_eq!(
        resolver, expected_actor,
        "the recovery actor is the resolver that served, or None with no set"
    );
    assert_eq!(notes[1], None, "no AAAA note is emitted");
    assert_eq!(
        transport.last_failure_origin(0, Family::A),
        configured.then_some(0),
        "the latest-failure origin is historical, survives recovery, and stays None with no set"
    );
    drop(responder);
}

/// Seats a receiver onto a configured two-resolver set with the primary active
/// and the allowlist bailiwick installed, the state the boot route leaves
/// before a lookups turn, so `step_recv` can be driven with a filled frame.
fn seeded_bailiwick_transport() -> StartupDns {
    let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8"]));
    transport
        .configure_bailiwick(&config())
        .expect("allowlist bailiwick installs over the seeded transport");
    transport
}

/// Builds the exact reply the startup receive path would parse for a positive A
/// answer at `ttl`: the outstanding query is assembled by the same
/// `wire::build_query` the send path uses, so the response question and owner
/// always match the fqdn/family/tid under test.
fn positive_a_reply(fqdn: &Fqdn, family: Family, tid: u16, ttl: u32, octets: [u8; 4]) -> Vec<u8> {
    let mut query = [0u8; QUERY_BUF_LEN];
    let qlen =
        wire::build_query(fqdn, family, tid, &mut query).expect("query fits the fixed buffer");
    positive_a_message(&query[..qlen], ttl, octets)
}

/// Places a complete length-prefixed reply into `recv_buf` exactly as a full
/// socket read would, with `msglen`/`filled` consistent, so `step_recv` parses
/// it with no connection and no wait.
fn fill_frame(transport: &mut StartupDns, msg: &[u8]) {
    let len = u16::try_from(msg.len()).expect("reply fits the u16 wire length");
    transport.recv_buf[..2].copy_from_slice(&len.to_be_bytes());
    transport.recv_buf[2..2 + msg.len()].copy_from_slice(msg);
    transport.filled = 2 + msg.len();
    transport.msglen = Some(msg.len());
}

/// Test-only derived route: an active resolver at `index` over a validated
/// non-empty `ResolverSet` of exactly `len` resolvers (1..=`MAX_RESOLVERS`) — the
/// set length comes from the set, never from a scalar `ActiveResolver`
/// argument; `with_index` then validates the selection.
fn active_at(len: usize, index: usize) -> ActiveResolver {
    let set = match len {
        2 => resolver_set_of(&["10.0.0.1", "10.0.0.2"]),
        _ => resolver_set_of(&["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
    };
    ActiveResolver::primary_of(&set)
        .with_index(index)
        .expect("in-range fixture")
}

#[cfg(test)]
mod shared_armed_cache;

mod exchange {
    use super::*;

    #[test]
    fn exchange_deadline_is_five_seconds_within_startup_budget() {
        assert_eq!(
            EXCHANGE_DEADLINE_SECS, 5,
            "the DNS exchange deadline is a single 5-second constant (alumina-5sx)"
        );
        let worst_case = MAX_RESOLVERS as u64 * DEGRADED_AFTER as u64 * EXCHANGE_DEADLINE_SECS;
        assert!(
            worst_case <= STARTUP_WINDOW_SECS,
            "worst-case all-resolvers-dead startup ({worst_case}s) must fit the \
         {STARTUP_WINDOW_SECS}s startup window"
        );
    }
    #[test]
    fn token_generation_exhaustion_is_rejected_not_wrapped() {
        let cfg = config();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.token_gen = usize::MAX;
        let err = transport
            .resolve(&cfg, &mut cache, &mut schedules, ns(0), 1_000_000)
            .expect_err("token generation exhaustion must be a typed error, never a wrap");
        assert_eq!(err, StartupDnsError::TokenExhausted);
    }
    #[test]
    fn storage_failure_escapes_resolve_as_err_not_a_counted_failure() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(1).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let err = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .expect_err(
                "a schedule-storage refusal on a later name must escape resolve as a fatal error",
            );
        assert!(
            matches!(err, StartupDnsError::Dns(wire::DnsError::Cache(_))),
            "storage refusal surfaces as Dns(Cache): {err:?}"
        );
    }
    #[test]
    fn extreme_ttl_positive_is_counted_as_a_dns_anomaly() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: wire::EXTREME_TTL_THRESHOLD + 1,
                octets: [93, 184, 216, 34],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 300,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        let anomalies = transport.take_dns_anomalies();
        assert_eq!(anomalies[DnsAnomalyKind::ExtremeTtl.index()], 1);
        assert_eq!(anomalies[DnsAnomalyKind::BailiwickViolation.index()], 0);
        assert_eq!(anomalies[DnsAnomalyKind::ResolverPeerMismatch.index()], 0);
        assert_eq!(
            transport.take_dns_anomalies(),
            [0, 0, 0, 0],
            "a drained anomaly is never double-counted"
        );
    }
    #[test]
    fn connected_peer_mismatch_fails_connect_and_counts_the_anomaly() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Close],
            vec![
                Step::PositiveAaaa {
                    ttl: 300,
                    octets: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                },
                Step::PositiveA {
                    ttl: 300,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.force_peer_mismatch = true;
        transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        let anomalies = transport.take_dns_anomalies();
        assert!(
            anomalies[DnsAnomalyKind::ResolverPeerMismatch.index()] >= 1,
            "every completed connect to a non-matching peer is flagged; got {}",
            anomalies[DnsAnomalyKind::ResolverPeerMismatch.index()]
        );
        assert_eq!(anomalies[DnsAnomalyKind::BailiwickViolation.index()], 0);
        assert_eq!(anomalies[DnsAnomalyKind::ExtremeTtl.index()], 0);
        assert_eq!(
            transport.take_dns_anomalies(),
            [0, 0, 0, 0],
            "a drained anomaly is never double-counted"
        );
    }
    #[test]
    fn connect_refused_counts_failure_and_sets_schedule_due() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let dead_port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let cfg = config();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(&cfg, &mut cache, &mut schedules, ns(dead_port), 1_000_000)
            .unwrap();
        assert_eq!(report.exchanges, 0);
        assert_eq!(report.failed, 4);
        assert_eq!(report.resolved_names, 0);
        for ordinal in 0..2 {
            for family in Family::ALL {
                assert!(
                    schedules.due_time(ordinal, family).unwrap().is_some(),
                    "a connect-refused exchange must still advance the schedule for ({ordinal}, {family:?})"
                );
            }
        }
    }
    #[test]
    fn mismatched_tid_fails_exchange_and_nothing_published_for_that_name() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::PositiveAMismatchedTid {
                ttl: 120,
                octets: [93, 184, 216, 34],
            }],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert!(
            bindings_of(&cache, 0, Family::A).is_empty(),
            "a mismatched-tid response must never publish"
        );
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }
    #[test]
    fn fragmented_partial_read_response_is_assembled_across_reads() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::FragmentedPositive {
                ttl: 120,
                octets: [93, 184, 216, 34],
                chunk: 1,
                gap: Duration::from_millis(2),
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.failed, 0);
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(93, 184, 216, 34)
            )]
        );
    }
    #[test]
    fn deadline_expiry_fails_exchange_without_publish_and_reconnects() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(3)), Step::Close],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert_eq!(bindings_of(&cache, 0, Family::A), []);
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }
    #[test]
    fn resolve_publishes_positives_and_nodata_across_one_connection() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.failed, 0);
        assert_eq!(report.cancelled, 0);
        assert_eq!(report.resolved_names, 2);
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(93, 184, 216, 34)
            )]
        );
        assert_eq!(bindings_of(&cache, 0, Family::Aaaa), []);
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
        let due = schedules.due_time(1, Family::A).unwrap().expect("due");
        let interval = due - 1_000_000;
        assert!(
            (90..=95).contains(&interval),
            "refresh from receipt + min(300, max(30,90)): {interval}"
        );
    }
    #[test]
    fn ineligible_only_positive_does_not_count_as_resolved_name() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 120,
                octets: [10, 0, 0, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.failed, 0);
        assert_eq!(
            report.resolved_names, 1,
            "an ineligible-only positive contributes no usable binding and must not count as resolved"
        );
        assert!(
            bindings_of(&cache, 1, Family::A).is_empty(),
            "the all-ineligible positive publishes no A binding"
        );
    }
    #[test]
    fn ineligible_only_positive_classifies_as_no_eligible() {
        let outcome = wire::Outcome::Positive {
            family: Family::A,
            bindings: wire::BindingList::from_slice(&[crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
            )])
            .expect("bindings"),
            ttl: 120,
        };
        assert_eq!(
            classify_published(&outcome),
            PublishedKind::NoEligible,
            "an all-ineligible positive must never be reported usable"
        );
        assert_ne!(
            classify_published(&outcome),
            PublishedKind::ResolvedPositive,
            "an all-ineligible positive must not count as a resolved positive"
        );
    }
    #[test]
    fn positive_aaaa_publishes_v6_binding_and_schedule() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::PositiveAaaa {
                ttl: 120,
                octets: [
                    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
                ],
            },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.failed, 0);
        assert_eq!(report.resolved_names, 2);
        assert_eq!(
            bindings_of(&cache, 0, Family::Aaaa),
            vec![crate::eligibility::NumericAddr::V6(
                std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)
            )]
        );
        let due = schedules.due_time(0, Family::Aaaa).unwrap().expect("due");
        let interval = due - 1_000_000;
        assert!(
            (120..=125).contains(&interval),
            "v6 refresh from receipt + min(300, max(30,120)): {interval}"
        );
    }
    #[test]
    fn malformed_response_fails_exchange_and_connection_is_reused_next() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Malformed(vec![1, 2, 3, 4])],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert_eq!(bindings_of(&cache, 0, Family::A), []);
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }
    #[test]
    fn stalled_responder_times_out_exchange_and_reconnects() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert!(
            responder.connections() >= 2,
            "a stalled-then-closed exchange must reconnect on a fresh connection"
        );
        assert_eq!(bindings_of(&cache, 0, Family::A), []);
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }
}

mod cooperative {
    use super::*;

    #[test]
    fn cooperative_silent_peer_yields_pending_before_deadline() {
        let cfg = config();
        let responder =
            spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        let deadline = Instant::now() + Duration::from_millis(400);
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Startup,
            )
            .unwrap();
        let first = transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap();
        assert!(
            matches!(first, TurnResult::Pending),
            "a turn with an unready peer must yield Pending without concluding, got {first:?}"
        );
        assert!(
            Instant::now() < deadline,
            "the exchange must not conclude before its absolute deadline"
        );
        let mut failures = 0;
        loop {
            match transport
                .advance_exchange(fqdn, &mut cache, &mut schedules)
                .unwrap()
            {
                TurnResult::Pending => {
                    let _ = transport.wait_dns_readiness(deadline).unwrap();
                }
                TurnResult::Failed(_) => {
                    failures += 1;
                    break;
                }
                TurnResult::Superseded => {
                    panic!("a silent peer must conclude as a counted failure, not superseded")
                }
                other @ TurnResult::Published(_) => {
                    panic!("a silent peer must conclude as a counted failure, got {other:?}")
                }
            }
        }
        assert_eq!(
            failures, 1,
            "the exchange must settle its counted failure exactly once"
        );
        assert!(
            schedules.due_time(0, Family::A).unwrap().is_some(),
            "a silent-peer failure must still advance the schedule backoff"
        );
        assert!(
            cache
                .entry(cache.name_index(0).unwrap(), Family::A)
                .unwrap()
                .bindings()
                .is_empty(),
            "a silent-peer exchange must not publish"
        );
        assert!(
            transport.conn.is_none(),
            "a failed exchange must close the connection for the next attempt"
        );
        drop(responder);
    }
    #[test]
    fn cooperative_advance_returns_control_to_worker_between_turns() {
        let cfg = config();
        let responder =
            spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        let deadline = Instant::now() + Duration::from_millis(400);
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Startup,
            )
            .unwrap();
        let mut worker_turns = 0u32;
        let mut terminal = None;
        for _ in 0..64 {
            match transport
                .advance_exchange(fqdn, &mut cache, &mut schedules)
                .unwrap()
            {
                TurnResult::Pending => {
                    worker_turns += 1;
                    if transport
                        .exchange_deadline()
                        .is_some_and(|d| Instant::now() >= d)
                    {
                        continue;
                    }
                    let _ = transport.wait_dns_readiness(deadline).unwrap();
                }
                other => {
                    terminal = Some(other);
                    break;
                }
            }
        }
        assert!(
            matches!(terminal, Some(TurnResult::Failed(_))),
            "a silent peer must conclude as a counted failure, got {terminal:?}"
        );
        assert!(
            worker_turns >= 2,
            "the worker must observe at least two bounded nonblocking turns before conclusion: {worker_turns}"
        );
        drop(responder);
    }
    #[test]
    fn cooperative_exchange_publishes_on_valid_response() {
        let ScriptedPositive {
            responder,
            mut transport,
            mut cache,
            mut schedules,
            fqdn,
            deadline,
        } = scripted_positive(120, [93, 184, 216, 34]);
        start_first_exchange(&mut transport, &fqdn, deadline, ExchangeClass::Startup);
        let result = drive_exchange_to_terminal(
            &mut transport,
            &fqdn,
            &mut cache,
            &mut schedules,
            deadline,
        )
        .expect("the exchange concludes");
        assert!(
            matches!(result, Ok(TurnResult::Published(_))),
            "a valid response must publish at the primitive level, got {result:?}"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(93, 184, 216, 34)
            )]
        );
        let due = schedules.due_time(0, Family::A).unwrap().expect("due");
        let interval = due - 1_000_000;
        assert!(
            (120..=125).contains(&interval),
            "refresh from receipt + min(300, max(30,120)): {interval}"
        );
        drop(responder);
    }
    #[test]
    fn cooperative_turn_performs_zero_blocking_polls() {
        let cfg = config();
        let responder =
            spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Startup,
            )
            .unwrap();
        for _ in 0..32 {
            let before = transport.poll_ticks;
            let res = transport
                .advance_exchange(fqdn, &mut cache, &mut schedules)
                .unwrap();
            assert_eq!(
                transport.poll_ticks, before,
                "advance_exchange must perform zero blocking polls per turn \
             (readiness waiting is the single owner's job), got turn {res:?}"
            );
        }
        let before = transport.poll_ticks;
        let _ready = transport
            .wait_dns_readiness(Instant::now() + Duration::from_millis(10))
            .unwrap();
        assert!(
            transport.poll_ticks > before,
            "only the owner-owned wait_dns_readiness is the sanctioned poll site"
        );
        drop(responder);
    }
    #[test]
    fn cooperative_send_wouldblock_makes_owner_wait_instead_of_busy_looping() {
        let ScriptedPositive {
            responder,
            mut transport,
            mut cache,
            mut schedules,
            fqdn,
            deadline,
        } = scripted_positive(120, [93, 184, 216, 34]);
        start_first_exchange(&mut transport, &fqdn, deadline, ExchangeClass::Startup);
        transport.arm_write(WriteForce::Partial(1));
        let mut guard = 0;
        loop {
            match transport.active_step() {
                Some(ExchangeStep::Connecting) => {
                    assert!(matches!(
                        advance_turn(&mut transport, &fqdn, &mut cache, &mut schedules),
                        TurnResult::Pending
                    ));
                    let _ = transport.wait_dns_readiness(deadline).unwrap();
                }
                Some(ExchangeStep::SendReady) => break,
                other => panic!("unexpected stage reaching the send path: {other:?}"),
            }
            guard += 1;
            assert!(guard < 16, "exchange did not reach the sending stage");
        }
        assert!(matches!(
            advance_turn(&mut transport, &fqdn, &mut cache, &mut schedules),
            TurnResult::Pending
        ));
        let before = transport.poll_ticks;
        let _ = transport.wait_dns_readiness(deadline).unwrap();
        assert_eq!(
            transport.poll_ticks, before,
            "after send progress the owner must not wait; the first send has \
         no wait and the next turn keeps pushing"
        );
        transport.arm_write(WriteForce::WouldBlock);
        assert!(matches!(
            advance_turn(&mut transport, &fqdn, &mut cache, &mut schedules),
            TurnResult::Pending
        ));
        let before = transport.poll_ticks;
        let _ = transport.wait_dns_readiness(deadline).unwrap();
        assert!(
            transport.poll_ticks > before,
            "after an actual sending WouldBlock the owner wait must perform a \
         real poll (awaiting-writable), not an instant-returning busy loop"
        );
        let result = drive_exchange_to_terminal(
            &mut transport,
            &fqdn,
            &mut cache,
            &mut schedules,
            deadline,
        )
        .expect("the exchange concludes");
        assert!(
            matches!(result, Ok(TurnResult::Published(_))),
            "a valid response must publish after an awaited would-block send, got {result:?}"
        );
        assert_ne!(bindings_of(&cache, 0, Family::A), []);
        drop(responder);
    }
}

mod startup {
    use super::*;

    #[test]
    fn startup_outcomes_report_latest_validated_negative_not_not_attempted() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![
                Step::NxdomainWithSoa { ttl: 300, min: 60 },
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::Stall(Duration::from_secs(3)),
                Step::Close,
            ],
            vec![Step::NodataWithSoa { ttl: 300, min: 60 }],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3, "name0 A, name0 AAAA, name1 AAAA");
        assert_eq!(
            report.failed, 1,
            "name1 A timed out on the stalled connection"
        );
        assert_eq!(
            report.outcomes[0],
            NameOutcome::Negative,
            "a validated NXDOMAIN/NODATA pair is negative, never not_attempted (T1)"
        );
        assert_eq!(
            report.outcomes[1],
            NameOutcome::Negative,
            "name1 AAAA NODATA is the latest concluded outcome, overriding the earlier timeout"
        );
        assert!(matches!(report.family_results[1][0], Some(Err(_))));
        assert_eq!(
            report.family_results[1][1],
            Some(Ok(PublishedKind::Negative))
        );
    }
    #[test]
    fn startup_outcome_failed_carries_latest_failure_reason() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::Stall(Duration::from_secs(6)),
                Step::Close,
            ],
            vec![Step::Stall(Duration::from_secs(6)), Step::Close],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 2);
        assert_eq!(report.failed, 2, "name1 A and AAAA both timed out");
        assert_eq!(
            report.outcomes[0],
            NameOutcome::Negative,
            "name0 stayed a validated negative"
        );
        assert_eq!(
            report.outcomes[1],
            NameOutcome::Failed(FailureReason::Timeout),
            "a name whose latest concluded exchanges all timed out carries the failure reason (T1)"
        );
    }
    #[cfg(feature = "alloc-witness")]
    #[test]
    /// Boot-window allocation witness: the ACTUAL startup DNS window is allocation-free
    /// including a transport reconnect. This qualifies the boot alloc-zero claim for a
    /// plain-DNS (bare-IP) resolver only: `config()`'s `resolver = ["1.1.1.1"]` keeps
    /// `upgrade_to_tls` unreachable, so `counts.all_zero()` does not cover a DoT-configured
    /// boot, which allocates in-window via the documented rustls bounded seam (`alumina-zai`).
    fn startup_dns_phase_is_allocation_free_including_reconnect() {
        use crate::alloc::{self, Phase};
        use crate::runtime::storage::{ServeStorage, StartupDecision};

        let ((), control) = alloc::run_phase(Phase::StartupDns, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            control.allocs > 0 && control.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {control:?}"
        );

        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Malformed(vec![0xff, 0xff, 0xff, 0xff])],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut storage =
            ServeStorage::boot(&cfg).expect("boot storage outside the measured window");

        let (outcome, counts) = alloc::run_phase(Phase::StartupDns, || {
            storage
                .run_startup_within(ns(responder.port()), 1_000_000, Duration::from_millis(700))
                .expect("production startup window")
        });
        assert!(
            counts.all_zero(),
            "the ACTUAL startup DNS window (resolve_window over booted storage, not the test driver resolve_body) must be allocation-free including a reconnect: {counts:?}"
        );
        assert!(
            matches!(outcome.decision(), StartupDecision::Exit75 { .. }),
            "both names unresolved under allowance 1 must exit 75 without binding a listener"
        );
        assert_eq!(outcome.report.resolved_names, 0);
        assert!(
            outcome.report.failed > 0,
            "the malformed first exchange plus the negative responses must count failures"
        );
        assert!(
            responder.connections() >= 2,
            "the malformed response must force a transport reconnect inside the measured window"
        );
        drop(responder);
    }
}

mod apply {
    use super::*;

    #[test]
    fn stale_generation_is_refused_at_apply() {
        let ScriptedPositive {
            responder,
            mut transport,
            mut cache,
            mut schedules,
            fqdn,
            deadline,
        } = scripted_positive(120, [1, 1, 1, 1]);
        let name_index = cache.name_index(0).unwrap();
        let captured = cache.entry(name_index, Family::A).unwrap().generation();
        assert_eq!(captured, Generation::INITIAL);
        transport
            .start_exchange(
                &fqdn,
                Family::A,
                0,
                deadline,
                captured,
                ExchangeClass::Startup,
            )
            .unwrap();
        // Bump the cache entry generation while the exchange is in flight so the
        // generation captured at start is stale when the response is applied.
        let staged = crate::dns::cache::StagedPositive::stage(
            name_index,
            Family::A,
            captured,
            &[crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1),
            )],
            transport.now_u64(),
            120,
        )
        .unwrap();
        cache.publish_positive(&staged).unwrap();
        let result = drive_exchange_to_terminal(
            &mut transport,
            &fqdn,
            &mut cache,
            &mut schedules,
            deadline,
        )
        .expect("the exchange concludes");
        assert!(
            matches!(
                result,
                Err(StartupDnsError::Dns(DnsError::Cache(
                    CacheError::StaleGeneration
                )))
            ),
            "an obsolete captured generation must refuse apply, got {result:?}"
        );
        drop(responder);
    }
    #[test]
    fn nxdomain_evicts_for_the_name_via_cache() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::NxdomainWithSoa { ttl: 300, min: 60 },
            Step::NxdomainWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.resolved_names, 1);
        assert_eq!(bindings_of(&cache, 0, Family::A), []);
        assert_eq!(bindings_of(&cache, 0, Family::Aaaa), []);
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }
    #[test]
    fn wait_until_next_step_with_no_scheduled_step_does_not_decide_early() {
        let transport = StartupDns::new().unwrap();
        let schedules = Schedules::new(2).unwrap();
        let resolved = [false, true];
        let wait = wait_until_next_step(&transport, &schedules, 2, &resolved).unwrap();
        assert!(
            wait > Duration::from_millis(100),
            "an unresolved name with no scheduled step must sleep toward the \
         window deadline, not break early: {wait:?}"
        );
    }
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "long two-part assertion that a refused second start leaves the first exchange surviving"
    )]
    fn start_active_exchange_is_refused_and_first_survives() {
        let cfg = config();
        let fqdn0 = cfg.allowlist().get(0).unwrap();
        let fqdn1 = cfg.allowlist().get(1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
        {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
            let dead_port = probe.local_addr().expect("probe addr").port();
            drop(probe);
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(dead_port);
            transport.now0 = 1_000_000;
            transport
                .start_exchange(
                    fqdn0,
                    Family::A,
                    0,
                    deadline,
                    Generation::INITIAL,
                    ExchangeClass::Startup,
                )
                .unwrap();
            let err = transport
                .start_exchange(
                    fqdn1,
                    Family::A,
                    1,
                    deadline,
                    Generation::INITIAL,
                    ExchangeClass::Startup,
                )
                .expect_err(
                    "a second start on an active exchange must be refused, never silently \
                 replace the outstanding exchange",
                );
            assert_eq!(
                err,
                StartupDnsError::ExchangeActive,
                "the refusal must be the typed ExchangeActive error"
            );
        }
        {
            let responder = spawn_responder(vec![vec![
                Step::PositiveA {
                    ttl: 120,
                    octets: [93, 184, 216, 34],
                },
                Step::Close,
            ]]);
            let mut cache = Cache::new(2).unwrap();
            let mut schedules = Schedules::new(2).unwrap();
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(responder.port());
            transport.now0 = 1_000_000;
            transport
                .start_exchange(
                    fqdn0,
                    Family::A,
                    0,
                    deadline,
                    Generation::INITIAL,
                    ExchangeClass::Startup,
                )
                .unwrap();
            let err = transport
                .start_exchange(
                    fqdn1,
                    Family::A,
                    1,
                    deadline,
                    Generation::INITIAL,
                    ExchangeClass::Startup,
                )
                .expect_err("a refused second start must not be absorbed or deferred; it is typed");
            assert_eq!(err, StartupDnsError::ExchangeActive);
            let mut result = None;
            for _ in 0..200 {
                match transport
                    .advance_exchange(fqdn0, &mut cache, &mut schedules)
                    .unwrap()
                {
                    TurnResult::Pending => {
                        if transport
                            .exchange_deadline()
                            .is_some_and(|d| Instant::now() >= d)
                        {
                            continue;
                        }
                        let _ = transport.wait_dns_readiness(deadline).unwrap();
                    }
                    term => {
                        result = Some(term);
                        break;
                    }
                }
            }
            assert!(
                matches!(result, Some(TurnResult::Published(_))),
                "the first exchange must still conclude despite the refused second start, got {result:?}"
            );
            assert_eq!(
                bindings_of(&cache, 0, Family::A),
                vec![crate::eligibility::NumericAddr::V4(
                    std::net::Ipv4Addr::new(93, 184, 216, 34)
                )]
            );
            assert!(
                bindings_of(&cache, 1, Family::A).is_empty(),
                "the refused second start must publish nothing and not advance its schedule"
            );
            drop(responder);
        }
    }
    #[test]
    fn stale_generation_apply_is_the_exact_typed_error_with_no_partial_commit() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_bailiwick_transport();
        let mut first = fixture_exchange(0, Family::A, ExchangeClass::Startup);
        first.tid = 0x1227;
        fill_frame(
            &mut transport,
            &positive_a_reply(fqdn, Family::A, first.tid, 120, [1, 1, 1, 1]),
        );
        assert!(
            matches!(
                transport
                    .step_recv(&mut first, fqdn, &mut cache, &mut schedules)
                    .unwrap(),
                RecvStep::Published(PublishedKind::ResolvedPositive)
            ),
            "the current-generation exchange publishes"
        );
        let mut stale = fixture_exchange(0, Family::A, ExchangeClass::Startup);
        stale.tid = 0x1228;
        fill_frame(
            &mut transport,
            &positive_a_reply(
                fqdn,
                Family::A,
                stale.tid,
                wire::EXTREME_TTL_THRESHOLD + 1,
                [10, 0, 0, 2],
            ),
        );
        let result = transport.step_recv(&mut stale, fqdn, &mut cache, &mut schedules);
        match result {
            Err(err) => assert_eq!(
                err,
                StartupDnsError::Dns(DnsError::Cache(CacheError::StaleGeneration)),
                "the apply refusal surfaces as the exact typed stale-generation error"
            ),
            Ok(_other) => panic!("an obsolete result must be refused, never published"),
        }
        assert_eq!(
            transport.dns_anomalies[DnsAnomalyKind::ExtremeTtl.index()],
            0,
            "a refused apply never counts the extreme TTL"
        );
        assert_eq!(
            transport.incident_opens, 0,
            "a refused apply never opens an incident"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1,)
            )],
            "the refused apply leaves the first exchange's published bindings intact"
        );
    }
    #[test]
    fn below_minimum_publication_is_counted_rejection_in_transport() {
        use crate::dns::cache::evidence::AssuranceRequirement;
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let mut cache =
            Cache::with_requirement(2, AssuranceRequirement::ResolverAuthenticated).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_bailiwick_transport();
        let mut ex = fixture_exchange(0, Family::A, ExchangeClass::Serving);
        ex.tid = 0x1230;
        fill_frame(
            &mut transport,
            &positive_a_reply(fqdn, Family::A, ex.tid, 120, [1, 2, 3, 4]),
        );
        let result = transport.step_recv(&mut ex, fqdn, &mut cache, &mut schedules);
        let Ok(RecvStep::Failed(reason)) = result else {
            panic!("a below-minimum candidate must settle as a counted rejection");
        };
        assert_eq!(
            reason,
            FailureReason::InsufficientAssurance,
            "the counted rejection carries the insufficient-assurance reason"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            Vec::new(),
            "the rejected candidate leaves the cache untouched"
        );
        assert_eq!(
            transport.take_incident_notes(),
            [
                Some(IncidentNote::Open {
                    ordinal: 0,
                    family: Family::A,
                    reason: FailureReason::InsufficientAssurance,
                    resolver: Some(0),
                }),
                None
            ],
            "the counted rejection opens a serving A incident typed by its reason"
        );
    }
}

mod cancel {
    use super::*;

    #[test]
    fn cancel_clears_startup_retained_exchange() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let dead_port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(dead_port);
        transport.now0 = 1_000_000;
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS),
                Generation::INITIAL,
                ExchangeClass::Startup,
            )
            .unwrap();
        assert!(
            transport.has_active_exchange(),
            "the startup exchange is in flight before the guard runs"
        );
        transport.cancel_retained_startup_exchange();
        assert!(
            !transport.has_active_exchange(),
            "the runtime guard cancels a retained startup exchange whose window expired"
        );
    }
    #[test]
    fn cancel_retains_serving_exchange() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let dead_port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(dead_port);
        transport.now0 = 1_000_000;
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS),
                Generation::INITIAL,
                ExchangeClass::Serving,
            )
            .unwrap();
        transport.cancel_retained_startup_exchange();
        assert!(
            transport.has_active_exchange(),
            "a serving-runtime refresh must never be cancelled by the startup guard"
        );
    }
    #[test]
    fn cancel_retains_probe_exchange() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let dead_port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(dead_port);
        transport.now0 = 1_000_000;
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS),
                Generation::INITIAL,
                ExchangeClass::Probe,
            )
            .unwrap();
        transport.cancel_retained_startup_exchange();
        assert!(
            transport.has_active_exchange(),
            "a post-window probe exchange must never be cancelled by the startup guard"
        );
    }
}

mod degraded {
    use super::*;

    #[test]
    fn resolver_enters_degraded_once_after_three_consecutive_failures() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        for _ in 0..3 {
            // A fresh deadline per exchange keeps every exchange dialing: the
            // responder scripts rely on one accepted connection per exchange.
            let deadline = Instant::now() + Duration::from_millis(200);
            transport
                .start_exchange(
                    fqdn,
                    Family::A,
                    0,
                    deadline,
                    Generation::INITIAL,
                    ExchangeClass::Startup,
                )
                .unwrap();
            assert!(
                matches!(
                    run_exchange_to_terminal(
                        &mut transport,
                        fqdn,
                        &mut cache,
                        &mut schedules,
                        deadline
                    ),
                    TurnResult::Failed(_)
                ),
                "each stalled exchange concludes as a counted failure"
            );
        }
        assert!(
            transport.resolver_degraded_for_test(),
            "the third consecutive failure relocates the resolver into degraded mode"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            1,
            "the enter crossing is emitted exactly once, never once per failure"
        );
        drop(responder);
    }
    #[test]
    fn resolver_failure_below_threshold_emits_no_transition_and_stays_healthy() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        for _ in 0..2 {
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                matches!(t, TurnResult::Failed(_))
            });
        }
        assert!(
            !transport.resolver_degraded_for_test(),
            "two consecutive failures are below the degraded threshold"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            0,
            "a below-threshold run never emits a resolver-degraded fact"
        );
        drop(responder);
    }
    #[test]
    fn resolver_stays_degraded_without_reemitting_on_further_failures() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        for _ in 0..4 {
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                matches!(t, TurnResult::Failed(_))
            });
        }
        assert!(
            transport.resolver_degraded_for_test(),
            "the fourth consecutive failure keeps the resolver degraded"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            1,
            "the fourth consecutive failure must not re-emit the degraded fact"
        );
        drop(responder);
    }
    #[test]
    fn successful_exchange_recovers_and_emits_exit_crossing_once() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let dead_port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let cfg = config();
        let responder = spawn_responder(vec![vec![Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        }]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(dead_port);
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        for _ in 0..3 {
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                matches!(t, TurnResult::Failed(_))
            });
        }
        assert!(
            transport.resolver_degraded_for_test(),
            "three consecutive connect-refused failures relocate the resolver into degraded mode"
        );
        transport.addr = ns(responder.port());
        run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
            matches!(t, TurnResult::Published(_))
        });
        assert!(
            !transport.resolver_degraded_for_test(),
            "a successful publication must leave degraded mode"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(93, 184, 216, 34)
            )],
            "the successful publication must publish the recovered answer"
        );
        transport.addr = ns(dead_port);
        for _ in 0..2 {
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                matches!(t, TurnResult::Failed(_))
            });
        }
        assert!(
            !transport.resolver_degraded_for_test(),
            "post-recovery failures restart the consecutive count from zero and \
         two never re-enter degraded mode"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            2,
            "exactly one enter and one exit crossing across the whole recovery arc"
        );
        drop(responder);
    }
    #[test]
    fn degraded_resolver_recovers_on_a_valid_negative_and_emits_exit_crossing() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        for _ in 0..3 {
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                matches!(t, TurnResult::Failed(_))
            });
        }
        assert!(
            transport.resolver_degraded_for_test(),
            "three consecutive failures relocate the resolver into degraded mode"
        );
        let negative = spawn_responder(vec![vec![Step::NxdomainWithSoa { ttl: 300, min: 60 }]]);
        transport.addr = ns(negative.port());
        run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
            matches!(t, TurnResult::Published(_))
        });
        assert!(
            !transport.resolver_degraded_for_test(),
            "a valid negative publishes and recovers the resolver out of degraded mode"
        );
        assert!(
            bindings_of(&cache, 0, Family::A).is_empty(),
            "the recovering exchange is a negative: no address bindings are published"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            2,
            "one enter and one exit crossing across the degraded/recovery arc"
        );
        drop(responder);
        drop(negative);
    }
}

mod anomaly {
    use super::*;

    #[test]
    fn genuinely_different_peer_address_is_rejected_without_the_force_seam() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![Step::Close]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        // The configured nameserver is a wildcard address; the loopback responder
        // accepts the dial, so the connected peer (127.0.0.1:port) genuinely
        // differs from the configured address (0.0.0.0:port) — no force seam.
        transport.addr = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
            matches!(t, TurnResult::Failed(_))
        });
        let anomalies = transport.take_dns_anomalies();
        assert!(
            anomalies[DnsAnomalyKind::ResolverPeerMismatch.index()] >= 1,
            "a genuinely different connected peer is counted as a resolver-peer anomaly"
        );
        drop(responder);
    }
    #[test]
    fn out_of_bailiwick_cname_is_recorded_as_a_transport_anomaly() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![Step::BailiwickViolationCname { ttl: 120 }]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        // StartupDns::new() leaves the bailiwick empty; set the real allowlist
        // zone so the CNAME escape is a genuine violation, not an empty-zone one.
        transport.bailiwick =
            BailiwickZones::from_allowlist(cfg.allowlist(), cfg.cname_bailiwick())
                .expect("validated config keeps suffix count within ALLOWLIST_MAX");
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
            matches!(t, TurnResult::Failed(_))
        });
        let anomalies = transport.take_dns_anomalies();
        assert_eq!(
            anomalies[DnsAnomalyKind::BailiwickViolation.index()],
            1,
            "a CNAME escaping the allowlist bailiwick is recorded exactly once"
        );
        assert_eq!(
            anomalies[DnsAnomalyKind::ResolverPeerMismatch.index()],
            0,
            "a bailiwick rejection is not a peer mismatch"
        );
        drop(responder);
    }
    #[test]
    fn zero_or_oversized_length_prefix_is_refused_fail_closed() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::LengthPrefixOnly { len: 0 }],
            vec![Step::LengthPrefixOnly {
                len: u16::try_from(DNS_MSG_LIMIT + 1)
                    .expect("oversized prefix fits u16 wire length"),
            }],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        let fqdn = cfg.allowlist().get(0).unwrap();
        for _ in 0..2 {
            // A long deadline gives the responder's close-probe (bounded by its
            // own 400ms read timeout) room to observe the guard's fail-closed
            // close before any hypothetical body-wait could reach the exchange
            // deadline; run_exchange_expecting's 200ms deadline is too short.
            let deadline = Instant::now() + Duration::from_secs(2);
            transport
                .start_exchange(
                    fqdn,
                    Family::A,
                    0,
                    deadline,
                    Generation::INITIAL,
                    ExchangeClass::Startup,
                )
                .unwrap();
            assert!(
                matches!(
                    run_exchange_to_terminal(
                        &mut transport,
                        fqdn,
                        &mut cache,
                        &mut schedules,
                        deadline
                    ),
                    TurnResult::Failed(_)
                ),
                "a zero or oversized length prefix fails the exchange closed"
            );
        }
        // The responder increments only after its probe observes the transport's
        // fail-closed close, which lands after the exchange reaches terminal; join
        // the responder (via drop) so both increments are final before asserting.
        let closed_after_prefix = Arc::clone(&responder.closed_after_prefix);
        drop(responder);
        assert_eq!(
            closed_after_prefix.load(Ordering::Relaxed),
            2,
            "both bad prefixes must be rejected by the length-prefix guard closing \
         the connection right after the 2-byte prefix, before any body read or parse"
        );
    }
    #[test]
    fn probe_observes_extreme_once_sets_kind_but_never_applies_state() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_bailiwick_transport();
        transport.corroboration = Some(Corroboration {
            target: active_at(2, 1),
            active_before: active_at(2, 0),
            ordinal: 0,
            family: Family::A,
        });
        let mut ex = fixture_exchange(0, Family::A, ExchangeClass::Probe);
        ex.tid = 0x1224;
        let due_before = schedules.due_time(0, Family::A);
        let reply = positive_a_reply(
            fqdn,
            Family::A,
            ex.tid,
            wire::EXTREME_TTL_THRESHOLD + 1,
            [1, 1, 1, 1],
        );
        fill_frame(&mut transport, &reply);
        let result = transport
            .step_recv(&mut ex, fqdn, &mut cache, &mut schedules)
            .unwrap();
        assert!(
            matches!(result, RecvStep::Published(PublishedKind::ResolvedPositive)),
            "a validated probe reply publishes the resolved-positive kind"
        );
        assert_eq!(
            transport.corroboration_outcome,
            Some(PublishedKind::ResolvedPositive),
            "a probe with a latched corroboration records the classified kind"
        );
        assert_eq!(
            transport.dns_anomalies[DnsAnomalyKind::ExtremeTtl.index()],
            1,
            "the probe counts the extreme TTL exactly once"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            Vec::new(),
            "a probe never publishes bindings"
        );
        assert_eq!(
            schedules.due_time(0, Family::A),
            due_before,
            "a probe never advances the refresh schedule"
        );
    }
    #[test]
    fn malformed_after_extreme_answer_is_a_receive_failure_not_an_extreme_anomaly() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_bailiwick_transport();
        let mut ex = fixture_exchange(0, Family::A, ExchangeClass::Startup);
        ex.tid = 0x1225;
        let mut reply = positive_a_reply(
            fqdn,
            Family::A,
            ex.tid,
            wire::EXTREME_TTL_THRESHOLD + 1,
            [1, 1, 1, 1],
        );
        reply.push(0xff);
        fill_frame(&mut transport, &reply);
        let result = transport
            .step_recv(&mut ex, fqdn, &mut cache, &mut schedules)
            .unwrap();
        assert!(
            matches!(result, RecvStep::Failed(FailureReason::Receive)),
            "a reply malformed after its extreme answer settles as a receive failure"
        );
        assert_eq!(
            transport.dns_anomalies[DnsAnomalyKind::ExtremeTtl.index()],
            0,
            "a parse failure never counts an extreme TTL the parse did not complete"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            Vec::new(),
            "a failed receive commits no bindings"
        );
    }
    #[test]
    fn valid_extreme_reply_past_the_deadline_times_out_before_any_observation() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_bailiwick_transport();
        let mut ex = fixture_exchange(0, Family::A, ExchangeClass::Startup);
        ex.tid = 0x1226;
        ex.deadline = Instant::now() - Duration::from_millis(1);
        let reply = positive_a_reply(
            fqdn,
            Family::A,
            ex.tid,
            wire::EXTREME_TTL_THRESHOLD + 1,
            [1, 1, 1, 1],
        );
        fill_frame(&mut transport, &reply);
        let result = transport
            .step_recv(&mut ex, fqdn, &mut cache, &mut schedules)
            .unwrap();
        assert!(
            matches!(result, RecvStep::Failed(FailureReason::Timeout)),
            "a reply arriving after the exchange deadline settles as a timeout"
        );
        assert_eq!(
            transport.dns_anomalies[DnsAnomalyKind::ExtremeTtl.index()],
            0,
            "the deadline closes the exchange before any observation is counted"
        );
        assert_eq!(
            transport.corroboration_outcome, None,
            "the timeout records no published kind"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            Vec::new(),
            "the timeout commits no cache state"
        );
    }
}

mod failover {
    use super::*;

    #[test]
    fn failover_relocates_to_next_healthy_after_threshold_and_arms_failback() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        transport.on_exchange_failed(now);
        transport.on_exchange_failed(now);
        assert_eq!(
            transport.active_resolver.index(),
            0,
            "two failures stay below the degraded threshold; no relocation"
        );
        assert!(
            transport.failback_due.is_none(),
            "no failback grace is armed while the active resolver is the primary"
        );
        transport.on_exchange_failed(now);
        assert_eq!(
            transport.active_resolver.index(),
            1,
            "the third consecutive failure relocates the transport onto the backup"
        );
        assert_eq!(transport.peer().ip().to_string(), "8.8.8.8");
        assert_eq!(transport.failback_due, Some(now + FAILBACK_AFTER_SECS));
        assert_eq!(
            transport.take_resolver_transitions(),
            1,
            "exactly one degraded enter crossing is emitted for the primary"
        );
        assert!(
            !transport.resolver_degraded_for_test(),
            "the relocated-to backup is the healthy active resolver"
        );
    }
    #[test]
    fn dot_to_plain_failover_counts_a_downgrade_but_dot_to_dot_and_plain_to_plain_do_not() {
        let now = 1_000_000u64;
        // A DoT primary (`IP#fqdn`) relocating onto a plain backup is a downgrade.
        let dot_set = {
            let mut entries = [crate::dns::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
            entries[0] = crate::dns::resolver::select("1.1.1.1#dns.google").expect("dot ns");
            entries[1] = crate::dns::resolver::select("8.8.8.8").expect("plain ns");
            ResolverSet::from_slice(&entries[..2]).expect("resolver count fits")
        };
        let mut transport = seeded_transport(dot_set);
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(
            transport.take_downgrade_to_plain(),
            1,
            "a DoT→plain failover relocation counts exactly one downgrade"
        );
        // A DoT primary relocating onto a DoT backup is not a downgrade.
        let dot_dot_set = {
            let mut entries = [crate::dns::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
            entries[0] = crate::dns::resolver::select("1.1.1.1#dns.google").expect("dot ns");
            entries[1] = crate::dns::resolver::select("8.8.8.8#dns.example").expect("dot ns");
            ResolverSet::from_slice(&entries[..2]).expect("resolver count fits")
        };
        let mut transport = seeded_transport(dot_dot_set);
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(
            transport.take_downgrade_to_plain(),
            0,
            "a DoT→DoT relocation is not a downgrade"
        );
        // A plain primary relocating onto a plain backup is not a downgrade.
        let plain_set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(plain_set);
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(
            transport.take_downgrade_to_plain(),
            0,
            "a plain→plain relocation is not a downgrade"
        );
    }
    #[test]
    fn single_resolver_fails_closed_keeping_the_injected_peer() {
        let set = resolver_set_of(&["1.1.1.1"]);
        let mut transport = seeded_transport(set);
        transport.set_peer_for_test(ns(53453));
        let now = 1_000_000u64;
        for _ in 0..5 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 0);
        assert_eq!(
            transport.peer(),
            ns(53453),
            "a single-resolver set never relocates or clobbers the injected peer"
        );
        assert!(transport.failback_due.is_none());
        assert!(transport.resolver_degraded_for_test());
    }
    #[test]
    fn three_resolvers_relocate_in_order_then_fail_closed_on_exhaustion() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 1, "primary -> backup 1");
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 2, "backup 1 -> backup 2");
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(
            transport.active_resolver.index(),
            2,
            "every resolver degraded; the transport fails closed on the last active"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            3,
            "one enter crossing per degraded resolver"
        );
    }
    #[test]
    fn five_resolvers_relocate_on_the_third_failure_not_the_fourth() {
        let addrs = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4", "2.2.2.2"];
        let set = resolver_set_of(&addrs);
        let mut transport = seeded_transport(set);
        transport.repoint_to_active();
        let now = 1_000_000u64;
        for resolver in 0..MAX_RESOLVERS {
            // The first two counted failures stay on the current resolver; the
            // third — the same transition that marks it degraded — relocates to
            // the next healthy resolver, or fail-closes on the last.
            transport.on_exchange_failed(now);
            assert_eq!(
                transport.active_resolver.index(),
                resolver,
                "failure {} stays on resolver {resolver}",
                3 * resolver + 1
            );
            assert_eq!(
                transport.peer().ip().to_string(),
                addrs[resolver],
                "the transport still dials resolver {resolver}"
            );
            transport.on_exchange_failed(now);
            assert_eq!(
                transport.active_resolver.index(),
                resolver,
                "failure {} stays on resolver {resolver}",
                3 * resolver + 2
            );
            transport.on_exchange_failed(now);
            let next = (resolver + 1).min(MAX_RESOLVERS - 1);
            assert_eq!(
                transport.active_resolver.index(),
                next,
                "failure {} relocates (or fail-closes on the last)",
                3 * (resolver + 1)
            );
            assert_eq!(
                transport.peer().ip().to_string(),
                addrs[next],
                "the transport repoints onto resolver {next}"
            );
        }
        assert_eq!(
            transport.active_resolver.index(),
            MAX_RESOLVERS - 1,
            "all five resolvers degraded: the transport fail-closes on the last"
        );
    }
    #[test]
    fn five_resolver_startup_budget_fits_the_window() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4", "2.2.2.2"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        // The complete five-resolver worst case is 15 exchanges: each resolver
        // degrades after three counted failures, and the third failure is the
        // same transition that relocates. At 5 s per exchange that is
        // 15 × 5 = 75 s, inside the 90 s startup window.
        for _ in 0..(MAX_RESOLVERS * DEGRADED_AFTER) {
            transport.on_exchange_failed(now);
        }
        assert_eq!(
            transport.active_resolver.index(),
            MAX_RESOLVERS - 1,
            "the last resolver holds after exhaustion (fail-closed)"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            MAX_RESOLVERS,
            "each resolver crosses into degraded exactly once"
        );
        assert!(
            MAX_RESOLVERS as u64 * DEGRADED_AFTER as u64 * EXCHANGE_DEADLINE_SECS
                <= STARTUP_WINDOW_SECS,
            "15 exchanges × 5 s = 75 s fits the 90 s startup window"
        );
    }
    #[test]
    fn next_healthy_wraps_within_the_set() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.degradations[0] = ResolverDegradation::Degraded;
        assert_eq!(
            transport.next_healthy_after_active(active_at(3, 2)),
            Some(active_at(3, 1)),
            "the scan wraps past the degraded primary back to the first healthy backup"
        );

        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.degradations[2] = ResolverDegradation::Degraded;
        assert_eq!(
            transport.next_healthy_after_active(active_at(3, 2)),
            Some(active_at(3, 0)),
            "a wrap around the set edge prefers a healthy primary"
        );

        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.degradations = [ResolverDegradation::Degraded; MAX_RESOLVERS];
        assert_eq!(
            transport.next_healthy_after_active(active_at(3, 1)),
            None,
            "every candidate degraded yields no relocation"
        );

        let set = resolver_set_of(&["1.1.1.1"]);
        let transport = seeded_transport(set);
        assert_eq!(
            transport.next_healthy_after_active(ActiveResolver::singleton()),
            None,
            "a single-resolver set never relocates"
        );
    }
    #[test]
    fn peer_matches_validates_the_active_resolver_only() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        let primary = SocketAddr::new("1.1.1.1".parse::<IpAddr>().expect("ip"), 53);
        let backup = SocketAddr::new("8.8.8.8".parse::<IpAddr>().expect("ip"), 53);
        assert!(
            transport.peer_matches(backup),
            "the connected peer matching the active backup resolver validates"
        );
        assert!(
            !transport.peer_matches(primary),
            "the inactive primary resolver no longer validates after failover"
        );
    }
}

mod failback {
    use super::*;

    #[test]
    fn failback_probes_primary_after_grace_and_success_recovers_it() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 1);
        let due = transport.failback_due.expect("failback armed on backup");
        assert!(due > now);
        // The failback grace elapses; the next exchange probes the primary again.
        transport.now0 = due;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        assert_eq!(
            transport.active_resolver.index(),
            0,
            "the probe dials the primary again"
        );
        assert_eq!(transport.peer().ip().to_string(), "1.1.1.1");
        assert_eq!(
            transport.failback_source,
            Some(active_at(2, 1)),
            "the backup is remembered so a failed probe re-seats onto it"
        );
        assert!(transport.failback_due.is_none());
        assert_eq!(
            transport.failback_successes, 0,
            "a new probe cycle starts with a zeroed consecutive-success counter"
        );
        // The first two probe successes do not settle the failback: the probe
        // stays armed until the third consecutive success.
        for _ in 0..2 {
            transport
                .on_exchange_succeeded()
                .expect("success settles without a transport error");
            assert_eq!(
                transport.failback_source,
                Some(active_at(2, 1)),
                "a single success does not settle the failback"
            );
            assert!(transport.failback_due.is_none());
        }
        assert_eq!(transport.failback_successes, 2);
        // The third consecutive probe success settles the failback.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(transport.active_resolver.index(), 0);
        assert!(transport.failback_source.is_none());
        assert!(transport.failback_due.is_none());
        assert_eq!(
            transport.failback_successes, 0,
            "the counter resets when the probe settles"
        );
        assert!(!transport.resolver_degraded_for_test());
        assert_eq!(
            transport.take_resolver_transitions(),
            2,
            "one enter crossing on degradation and one exit crossing on the first probe success"
        );
    }
    #[test]
    fn failback_does_not_settle_on_one_or_two_probe_successes() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        let due = transport.failback_due.expect("failback armed");
        transport.now0 = due;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        assert_eq!(transport.active_resolver.index(), 0);
        assert!(transport.failback_source.is_some());
        // One success is not enough to settle the probe.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(
            transport.failback_source,
            Some(active_at(2, 1)),
            "one success leaves the probe armed"
        );
        assert_eq!(transport.failback_successes, 1);
        // Two successes are still not enough.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(
            transport.failback_source,
            Some(active_at(2, 1)),
            "two successes leave the probe armed"
        );
        assert_eq!(transport.failback_successes, 2);
        assert!(transport.failback_due.is_none());
    }
    #[test]
    fn failed_probe_mid_regime_resets_counter_and_reseats() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        let due = transport.failback_due.expect("failback armed");
        transport.now0 = due;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        // Two successes advance the counter into the middle of the regime.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(transport.failback_successes, 2);
        // A failed probe mid-regime re-seats onto the backup, re-arms the grace,
        // and resets the counter so the next cycle starts from zero.
        transport.on_exchange_failed(due);
        assert_eq!(
            transport.active_resolver.index(),
            1,
            "a failed probe re-seats onto the backup it came from"
        );
        assert_eq!(transport.peer().ip().to_string(), "8.8.8.8");
        assert!(transport.failback_source.is_none());
        assert_eq!(
            transport.failback_successes, 0,
            "a failed probe resets the consecutive-success counter"
        );
        assert_eq!(
            transport.failback_due,
            Some(due + FAILBACK_AFTER_SECS),
            "the failed probe re-arms the failback timer"
        );
    }
    #[test]
    fn failed_dot_probe_reseating_onto_plain_backup_counts_a_downgrade() {
        let dot_set = {
            let mut entries = [crate::dns::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
            entries[0] = crate::dns::resolver::select("1.1.1.1#dns.google").expect("dot ns");
            entries[1] = crate::dns::resolver::select("8.8.8.8").expect("plain ns");
            ResolverSet::from_slice(&entries[..2]).expect("resolver count fits")
        };
        let mut transport = seeded_transport(dot_set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(
            transport.take_downgrade_to_plain(),
            1,
            "the initial DoT→plain failover counts one downgrade"
        );
        let due = transport.failback_due.expect("failback armed on backup");
        transport.now0 = due;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        assert_eq!(transport.active_resolver.index(), 0);
        // The failed probe re-seats from the DoT primary onto the plain backup.
        transport.on_exchange_failed(due);
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(
            transport.take_downgrade_to_plain(),
            1,
            "the DoT→plain failback re-seat counts a second downgrade"
        );
    }
    #[test]
    fn failback_begin_from_dot_backup_onto_plain_primary_counts_a_downgrade() {
        // A plain primary with a DoT backup: the failover onto the DoT backup is
        // not a downgrade, but the failback-begin relocation back onto the plain
        // primary IS a DoT→plain downgrade that must be counted (G6-C01).
        let plain_dot_set = {
            let mut entries = [crate::dns::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
            entries[0] = crate::dns::resolver::select("1.1.1.1").expect("plain ns");
            entries[1] = crate::dns::resolver::select("8.8.8.8#dns.google").expect("dot ns");
            ResolverSet::from_slice(&entries[..2]).expect("resolver count fits")
        };
        let mut transport = seeded_transport(plain_dot_set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(
            transport.take_downgrade_to_plain(),
            0,
            "a plain→DoT failover relocation is not a downgrade"
        );
        let due = transport.failback_due.expect("failback armed on backup");
        transport.now0 = due;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        assert_eq!(transport.active_resolver.index(), 0);
        assert_eq!(
            transport.take_downgrade_to_plain(),
            1,
            "the failback-begin relocation from the DoT backup onto the plain primary \
         counts a downgrade"
        );
    }
    #[test]
    fn backup_success_leaves_failback_counter_at_zero() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        let due = transport.failback_due.expect("failback armed");
        assert_eq!(transport.active_resolver.index(), 1);
        // A success on the backup leaves the counter and the grace untouched.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(transport.failback_successes, 0);
        assert_eq!(transport.failback_due, Some(due));
        assert!(transport.failback_source.is_none());
    }
    #[test]
    fn failed_failback_probe_reseats_onto_backup_and_rearms_timer() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        let due = transport.failback_due.expect("failback armed");
        transport.now0 = due;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        assert_eq!(transport.active_resolver.index(), 0);
        assert!(transport.failback_source.is_some());
        // The probe against the primary fails: the transport re-seats onto the
        // backup and re-arms the grace instead of cascading into a second failover
        // candidate search.
        transport.on_exchange_failed(due);
        assert_eq!(
            transport.active_resolver.index(),
            1,
            "a failed probe re-seats onto the backup it came from"
        );
        assert_eq!(transport.peer().ip().to_string(), "8.8.8.8");
        assert!(transport.failback_source.is_none());
        assert_eq!(
            transport.failback_due,
            Some(due + FAILBACK_AFTER_SECS),
            "the failed probe re-arms the failback timer"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            1,
            "only the original primary enter crossing; the backup never degraded"
        );
    }
    #[test]
    fn backup_success_keeps_the_failback_probe_armed() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        let due = transport.failback_due.expect("failback armed");
        // The backup succeeds; the primary is still probed at the next due
        // exchange because the failback grace stays armed on a non-primary.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(transport.failback_due, Some(due));
        assert!(transport.failback_source.is_none());
    }
    #[test]
    fn probe_begin_mid_regime_does_not_reset_the_failback_counter() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        let due = transport.failback_due.expect("failback armed");
        transport.now0 = due;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        assert_eq!(transport.failback_successes, 0);
        assert_eq!(
            transport.failback_source,
            Some(active_at(2, 1)),
            "the backup is remembered so a failed probe re-seats onto it"
        );
        // The first probe success advances the counter into the middle of the
        // regime while the probe stays armed on the primary.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(transport.failback_successes, 1);
        // A later exchange re-enters the probe-begin path while the probe is
        // already armed; it must NOT reset the counter. A literal "reset on every
        // probe begin" would make the third consecutive success unreachable.
        transport
            .maybe_begin_failback()
            .expect("armed probe-begin is a no-op");
        assert_eq!(
            transport.failback_successes, 1,
            "a probe begin mid-regime does not reset the consecutive-success counter"
        );
        // A failed probe mid-regime re-seats onto the backup, re-arms the grace,
        // and resets the counter so the next cycle starts from zero.
        transport.on_exchange_failed(due);
        assert_eq!(transport.active_resolver.index(), 1);
        assert_eq!(transport.failback_successes, 0);
        assert_eq!(
            transport.failback_due,
            Some(due + FAILBACK_AFTER_SECS),
            "the failed probe re-arms the failback timer"
        );
        // The grace elapses again; the next probe begins a fresh cycle.
        transport.now0 = due + FAILBACK_AFTER_SECS;
        transport
            .maybe_begin_failback()
            .expect("failback probe begins");
        assert_eq!(transport.failback_successes, 0);
        // Two successes advance the counter to two; a probe begin still does not
        // reset it mid-regime.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(transport.failback_successes, 2);
        transport
            .maybe_begin_failback()
            .expect("armed probe-begin is a no-op");
        assert_eq!(
            transport.failback_successes, 2,
            "a probe begin mid-regime does not reset the consecutive-success counter"
        );
        // The third consecutive success settles the failback.
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(transport.active_resolver.index(), 0);
        assert!(transport.failback_source.is_none());
        assert!(transport.failback_due.is_none());
        assert_eq!(
            transport.failback_successes, 0,
            "the counter resets when the probe settles"
        );
    }
}

mod probe_sweep {
    use super::*;

    #[test]
    fn probe_sweep_does_not_begin_for_single_resolver_set() {
        let set = resolver_set_of(&["1.1.1.1"]);
        let mut transport = seeded_transport(set);
        transport.maybe_begin_sweep();
        assert!(
            !transport.sweep_active(),
            "a single-resolver set short-circuits: no post-window probe sweep begins"
        );
        assert!(
            transport.probe_sweep.is_none(),
            "the sweep state stays absent for a single-resolver set"
        );
    }
    #[test]
    fn probe_sweep_begins_for_multi_resolver_set_skipping_the_active_resolver() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.maybe_begin_sweep();
        assert!(
            transport.sweep_active(),
            "the sweep begins for a multi-resolver set"
        );
        let sweep = transport.probe_sweep.expect("sweep began");
        assert_eq!(
            sweep.active_before,
            active_at(3, 0),
            "the pre-sweep active resolver (the primary) is remembered for restore"
        );
        assert_eq!(
            sweep.remaining,
            [false, true, true, false, false],
            "the active resolver is skipped; only the unexercised resolvers remain"
        );
        assert_eq!(
            sweep.verdicts,
            [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            "every verdict starts as not probed"
        );
        assert_eq!(sweep.current, None, "no probe is in flight yet");
    }
    #[test]
    fn probe_sweep_skips_every_resolver_the_window_exercised() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.active_resolver = active_at(3, 1);
        transport.window_exercised = [true, true, false, false, false];
        transport.maybe_begin_sweep();
        assert!(
            transport.sweep_active(),
            "the sweep begins for a multi-resolver set"
        );
        let sweep = transport.probe_sweep.expect("sweep began");
        assert_eq!(
            sweep.remaining,
            [false, false, true, false, false],
            "every resolver the window exercised is skipped; only the untouched index 2 remains"
        );
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        let done = transport.sweep_next_probe(&fqdn).expect("probe starts");
        assert!(!done, "the single untouched resolver is probed");
        assert_eq!(
            transport.probe_sweep.as_ref().expect("sweep").current,
            Some(active_at(3, 2)),
            "the probe targets the only unexercised resolver"
        );
        let mut schedules = Schedules::new(2).unwrap();
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Probe),
                &mut schedules,
                FailureReason::Connect,
            )
            .expect("failure noted");
        let sweep = transport.probe_sweep.expect("sweep still active");
        assert_eq!(
            sweep.verdicts[1],
            ProbeVerdict::NotProbed,
            "the exercised active resolver is never probed and keeps no verdict"
        );
        assert_eq!(
            sweep.verdicts[2],
            ProbeVerdict::Failed(FailureReason::Connect),
            "the unexercised resolver receives the probe verdict"
        );
    }
    #[test]
    fn probe_sweep_does_not_re_begin_after_verdicts_are_taken() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        transport.maybe_begin_sweep();
        assert!(transport.sweep_active());
        transport.take_sweep_verdicts();
        assert!(
            !transport.sweep_active(),
            "taking the verdicts clears the sweep state"
        );
        transport.maybe_begin_sweep();
        assert!(
            !transport.sweep_active(),
            "the completed sweep never re-begins on a later turn"
        );
    }
    #[test]
    fn probe_sweep_does_not_begin_while_a_failback_probe_is_in_flight() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        transport.failback_source = Some(active_at(2, 1));
        transport.maybe_begin_sweep();
        assert!(
            !transport.sweep_active(),
            "an in-flight failback probe defers the sweep so the two probes never overlap"
        );
    }
    #[test]
    fn sweep_next_probe_relocates_and_starts_the_first_unprobed_resolver() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.maybe_begin_sweep();
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        let done = transport.sweep_next_probe(&fqdn).expect("probe starts");
        assert!(!done, "the sweep is not done after starting one probe");
        let sweep = transport.probe_sweep.expect("sweep still active");
        assert_eq!(
            sweep.current,
            Some(active_at(3, 1)),
            "the first unprobed resolver is index 1"
        );
        assert_eq!(
            sweep.remaining,
            [false, false, true, false, false],
            "the started resolver leaves the remaining set"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(3, 1),
            "the transport relocates onto the probe target"
        );
        assert_eq!(transport.peer().ip().to_string(), "8.8.8.8");
        assert!(
            transport.has_active_exchange(),
            "the probe exchange is in flight"
        );
        assert!(
            transport
                .active
                .as_ref()
                .is_some_and(|ex| ex.class == ExchangeClass::Probe),
            "the sweep probe exchange is classed Probe so the serving runtime's \
         startup-cancellation guard never mistakes it for retained startup work"
        );
    }
    #[test]
    fn sweep_next_probe_returns_done_when_every_resolver_is_probed() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, false, false, false, false],
            active_before: active_at(2, 0),
            verdicts: [
                ProbeVerdict::Ok,
                ProbeVerdict::Failed(FailureReason::Connect),
                ProbeVerdict::NotProbed,
                ProbeVerdict::NotProbed,
                ProbeVerdict::NotProbed,
            ],
            current: None,
        });
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        let done = transport.sweep_next_probe(&fqdn).expect("no probe starts");
        assert!(
            done,
            "no unprobed resolver remains, so the sweep is complete"
        );
        assert!(
            !transport.has_active_exchange(),
            "no exchange is started when the sweep is already complete"
        );
    }
    #[test]
    fn sweep_next_probe_returns_false_while_a_probe_is_in_flight() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.maybe_begin_sweep();
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        transport
            .sweep_next_probe(&fqdn)
            .expect("first probe starts");
        let done = transport.sweep_next_probe(&fqdn).expect("no second probe");
        assert!(
            !done,
            "an in-flight probe defers the next probe rather than starting a second one"
        );
        let sweep = transport.probe_sweep.expect("sweep still active");
        assert_eq!(
            sweep.current,
            Some(active_at(3, 1)),
            "the in-flight probe is untouched"
        );
    }
    #[test]
    fn failed_probe_advances_probed_degradation_restores_active_and_records_no_failback() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, false, true, false, false],
            active_before: active_at(3, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(3, 2)),
        });
        transport.active_resolver = active_at(3, 2);
        transport.repoint_to_active();
        transport.on_exchange_failed(now);
        assert_eq!(
            transport.active_resolver,
            active_at(3, 0),
            "a failed probe restores the pre-sweep active resolver"
        );
        assert_eq!(transport.peer().ip().to_string(), "1.1.1.1");
        assert!(
            transport.failback_due.is_none(),
            "a sweep probe failure never arms the failback grace"
        );
        assert!(
            transport.failback_source.is_none(),
            "a sweep probe failure never arms a failback probe"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            0,
            "one failure stays below the degraded threshold; no rd= crossing yet"
        );
        assert_eq!(
            transport
                .probe_sweep
                .as_ref()
                .expect("sweep active")
                .current,
            Some(active_at(3, 2)),
            "the probe target stays current so the caller records the verdict with its reason"
        );
    }
    #[test]
    fn failed_probe_at_threshold_emits_degraded_enter_crossing_for_the_probed_resolver() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, false, true, false, false],
            active_before: active_at(3, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(3, 2)),
        });
        transport.active_resolver = active_at(3, 2);
        transport.repoint_to_active();
        for _ in 0..3 {
            transport.on_exchange_failed(now);
        }
        assert_eq!(
            transport.take_resolver_transitions(),
            1,
            "the third consecutive probe failure crosses the probed resolver into degraded"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(3, 0),
            "the probe failure still restores the pre-sweep active resolver"
        );
    }
    #[test]
    fn successful_probe_records_ok_resets_probed_and_restores_active() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, false, true, false, false],
            active_before: active_at(3, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(3, 2)),
        });
        transport.active_resolver = active_at(3, 2);
        transport.repoint_to_active();
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert_eq!(
            transport.active_resolver,
            active_at(3, 0),
            "a successful probe restores the pre-sweep active resolver"
        );
        assert_eq!(transport.peer().ip().to_string(), "1.1.1.1");
        let sweep = transport.probe_sweep.expect("sweep still active");
        assert_eq!(sweep.current, None, "the probe target clears on success");
        assert_eq!(
            sweep.verdicts[2],
            ProbeVerdict::Ok,
            "the successful probe records an ok verdict"
        );
        assert!(
            transport.failback_source.is_none(),
            "a sweep probe success never touches the failback machinery"
        );
    }
    #[test]
    fn successful_probe_closes_retained_connection_so_the_next_exchange_redials() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, false, true, false, false],
            active_before: active_at(3, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(3, 2)),
        });
        transport.active_resolver = active_at(3, 2);
        transport.repoint_to_active();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe peer");
        let client = mio::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        transport.conn = Some(DnsConn::Plain {
            stream: client,
            source: ResolverSource::UNKNOWN,
        });
        transport
            .on_exchange_succeeded()
            .expect("success settles without a transport error");
        assert!(
            transport.conn.is_none(),
            "a successful sweep probe must close the retained probe-target connection"
        );
        assert_eq!(
            transport.probe_connect(),
            ConnectProbe::NotReady,
            "with the connection closed the next exchange re-dials instead of reusing the stale peer"
        );
        assert_eq!(
            transport.take_dns_anomalies()[DnsAnomalyKind::ResolverPeerMismatch.index()],
            0,
            "no resolver-peer mismatch is counted on the exchange after a successful sweep probe"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(3, 0),
            "the pre-sweep active resolver is restored"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            0,
            "a successful probe never degrades or transitions the restored active resolver"
        );
    }
    #[test]
    fn probe_exchange_publishes_no_name_authorization_state() {
        // F-03: a post-window probe is a pure sensor. It parses and validates a
        // response to record a verdict, but must never mutate name-authorization
        // state (cache bindings, refresh schedule). The active exchange on the
        // same name DOES apply the outcome, so the probe's non-mutation is
        // observable byte-for-byte.
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let responder = spawn_responder(vec![
            // Connection 1: the active exchange publishes a 120s positive.
            vec![Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            }],
            // Connection 2: the probe exchange returns a different positive; if
            // the probe wrongly applied the outcome the mutation would be visible.
            vec![Step::PositiveA {
                ttl: 300,
                octets: [1, 1, 1, 1],
            }],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]));
        transport.addr = ns(responder.port());
        // Seed the post-window probe sweep directly (the established probe-sweep
        // test pattern): index 1 is the sole unprobed resolver and the pre-sweep
        // active resolver stays the primary. `resolvers` is cleared so
        // `repoint_to_active` never overrides the injected responder peer and the
        // probe dials `addr` above, not a real resolver.
        transport.resolvers = None;
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, true, false, false, false],
            active_before: active_at(3, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: None,
        });

        // Phase 1: a normal active exchange publishes name-authorization state.
        let deadline = Instant::now() + Duration::from_millis(200);
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Startup,
            )
            .unwrap();
        assert!(
            matches!(
                run_exchange_to_terminal(
                    &mut transport,
                    fqdn,
                    &mut cache,
                    &mut schedules,
                    deadline
                ),
                TurnResult::Published(_)
            ),
            "the active exchange publishes its outcome"
        );
        let bindings_before = bindings_of(&cache, 0, Family::A);
        let due_before = schedules.due_time(0, Family::A).unwrap();
        assert_ne!(
            bindings_before,
            [],
            "the active exchange established bindings"
        );
        assert!(
            due_before.is_some(),
            "the active exchange committed a refresh schedule"
        );

        // Phase 2: the probe exchange must leave that state byte-for-byte intact.
        let done = transport
            .sweep_next_probe(fqdn)
            .expect("the probe exchange starts");
        assert!(!done, "the sweep is not done after starting the probe");
        let probe_deadline = Instant::now() + Duration::from_secs(5);
        assert!(
            matches!(
                run_exchange_to_terminal(
                    &mut transport,
                    fqdn,
                    &mut cache,
                    &mut schedules,
                    probe_deadline
                ),
                TurnResult::Published(_)
            ),
            "the probe exchange still publishes so the verdict is recorded"
        );
        let sweep = transport.probe_sweep.expect("sweep still active");
        assert_eq!(
            sweep.verdicts[1],
            ProbeVerdict::Ok,
            "the probe records its ok verdict against the probed resolver"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(3, 0),
            "the probe restores the pre-sweep active resolver"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            bindings_before,
            "a probe must never publish name bindings"
        );
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            due_before,
            "a probe must never commit a refresh schedule"
        );
        drop(responder);
    }
    #[test]
    fn sweep_probe_to_non_primary_is_never_hijacked_into_a_failback_probe() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        let now = 1_000_000u64;
        // A window failover to the backup arms the failback grace with no source.
        transport.active_resolver = active_at(3, 1);
        transport.repoint_to_active();
        transport.failback_due = Some(now + FAILBACK_AFTER_SECS);
        transport.failback_source = None;
        // The sweep begins and probes the non-primary index 2.
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, true, true, false, false],
            active_before: active_at(3, 1),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(3, 2)),
        });
        transport.active_resolver = active_at(3, 2);
        transport.repoint_to_active();
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
        transport
            .start_exchange(
                &fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Startup,
            )
            .expect("probe exchange begins");
        assert_eq!(
            transport.active_resolver,
            active_at(3, 2),
            "the sweep probe to a non-primary is not re-routed to the primary by failback"
        );
        assert_eq!(
            transport.failback_source, None,
            "the failback machinery stays unarmed during the sweep probe"
        );
        assert_eq!(
            transport.failback_due,
            Some(now + FAILBACK_AFTER_SECS),
            "the pre-existing failback grace is untouched by the sweep probe"
        );
    }
    #[test]
    fn shutdown_aborts_the_sweep_and_drops_partial_verdicts() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, true, true, false, false],
            active_before: active_at(3, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(3, 2)),
        });
        transport.active_resolver = active_at(3, 2);
        transport.repoint_to_active();
        transport.cancel_for_shutdown();
        assert!(
            !transport.sweep_active(),
            "shutdown clears the sweep so partial verdicts are never emitted"
        );
        assert!(
            !transport.has_active_exchange(),
            "shutdown clears the outstanding probe exchange"
        );
    }
    #[test]
    fn relocate_for_probe_counts_a_probe_relocation_and_restores_without_extra() {
        let dot_set = {
            let mut entries = [crate::dns::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
            entries[0] = crate::dns::resolver::select("1.1.1.1#dns.google").expect("dot ns");
            entries[1] = crate::dns::resolver::select("8.8.8.8").expect("plain ns");
            ResolverSet::from_slice(&entries[..2]).expect("resolver count fits")
        };
        let mut transport = seeded_transport(dot_set);
        transport
            .relocate_for_probe(active_at(2, 1))
            .expect("relocation succeeds");
        assert_eq!(
            transport.active_resolver,
            active_at(2, 1),
            "the probe relocation seats the transport onto the probe target"
        );
        assert_eq!(transport.peer().ip().to_string(), "8.8.8.8");
        assert_eq!(
            transport.take_downgrade_to_plain(),
            0,
            "a probe-sweep relocation is not a serving downgrade and never folds into dp="
        );
        assert_eq!(
            transport.take_probe_relocations(),
            1,
            "relocating onto a probe target counts a probe relocation"
        );
        // A failed probe restores the pre-sweep active resolver; the restore is a
        // sweep restore, not a relocation, so no second probe relocation is counted.
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, false, false, false, false],
            active_before: active_at(2, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(2, 1)),
        });
        transport.on_exchange_failed(1_000_000u64);
        assert_eq!(transport.active_resolver, active_at(2, 0));
        assert_eq!(
            transport.take_probe_relocations(),
            0,
            "restoring the pre-sweep resolver counts no additional probe relocation"
        );
    }
}

mod note_failure {
    use super::*;

    #[test]
    fn note_failure_records_failed_verdict_with_reason_and_clears_current() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        let mut transport = seeded_transport(set);
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, false, true, false, false],
            active_before: active_at(3, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(3, 2)),
        });
        transport.active_resolver = active_at(3, 2);
        transport.repoint_to_active();
        let mut schedules = Schedules::new(2).unwrap();
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Probe),
                &mut schedules,
                FailureReason::Connect,
            )
            .expect("failure noted");
        let sweep = transport.probe_sweep.expect("sweep still active");
        assert_eq!(sweep.current, None, "the verdict recording clears current");
        assert_eq!(
            sweep.verdicts[2],
            ProbeVerdict::Failed(FailureReason::Connect),
            "the failure reason is captured in the probe verdict"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(3, 0),
            "note_failure flows through the probe-mode restore"
        );
        assert_eq!(
            transport.last_failure_origin(0, Family::A),
            None,
            "a probe failure never writes name failure metadata"
        );
    }
    #[test]
    fn note_failure_serving_accumulates_open_note_on_first_failure() {
        let set = resolver_set_of(&["1.1.1.1"]);
        let mut transport = seeded_transport(set);
        let mut schedules = Schedules::new(2).unwrap();
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Connect,
            )
            .expect("failure noted");
        assert_eq!(
            transport.take_incident_notes(),
            [
                Some(IncidentNote::Open {
                    ordinal: 0,
                    family: Family::A,
                    reason: FailureReason::Connect,
                    resolver: Some(0),
                }),
                None,
            ],
            "a serving first failure accumulates exactly one open note"
        );
    }
    #[test]
    fn note_failure_startup_suppresses_open_note_but_tracks_state() {
        let set = resolver_set_of(&["1.1.1.1"]);
        let mut transport = seeded_transport(set);
        let mut schedules = Schedules::new(2).unwrap();
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Startup),
                &mut schedules,
                FailureReason::Connect,
            )
            .expect("startup failure noted");
        assert_eq!(
            transport.last_failure_origin(0, Family::A),
            Some(0),
            "the startup failure retains its origin for incident-summary seeding"
        );
        assert_eq!(
            transport.take_incident_notes(),
            [None, None],
            "a startup first failure emits no open note"
        );
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Timeout,
            )
            .expect("serving failure noted");
        assert_eq!(
            transport.take_incident_notes(),
            [None, None],
            "the incident opened during startup, so the serving failure is a silent update"
        );
    }
    #[test]
    fn note_failure_silent_update_does_not_accumulate_second_note() {
        let set = resolver_set_of(&["1.1.1.1"]);
        let mut transport = seeded_transport(set);
        let mut schedules = Schedules::new(2).unwrap();
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Connect,
            )
            .expect("first failure noted");
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Timeout,
            )
            .expect("second failure noted");
        assert_eq!(
            transport.take_incident_notes(),
            [
                Some(IncidentNote::Open {
                    ordinal: 0,
                    family: Family::A,
                    reason: FailureReason::Connect,
                    resolver: Some(0),
                }),
                None,
            ],
            "a silent update while open emits no second note"
        );
    }
    #[test]
    fn note_failure_retains_failed_origin_per_family_after_third_failure_relocation() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let mut schedules = Schedules::new(2).unwrap();
        assert_eq!(
            transport.current_resolver_index(),
            Some(0),
            "the primary is current before any failure"
        );
        transport
            .note_failure(
                &fixture_exchange(0, Family::A, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Connect,
            )
            .expect("first failure noted");
        assert_eq!(
            transport.take_incident_notes(),
            [
                Some(IncidentNote::Open {
                    ordinal: 0,
                    family: Family::A,
                    reason: FailureReason::Connect,
                    resolver: Some(0),
                }),
                None,
            ],
            "the open origin is the failing resolver 0, before any relocation"
        );
        for _ in 0..2 {
            transport
                .note_failure(
                    &fixture_exchange(0, Family::A, ExchangeClass::Serving),
                    &mut schedules,
                    FailureReason::Timeout,
                )
                .expect("advance toward degradation");
        }
        assert_eq!(
            transport.active_resolver.index(),
            1,
            "the third consecutive failure relocated the current resolver onto the backup"
        );
        assert_eq!(
            transport.current_resolver_index(),
            Some(1),
            "current configured resolver is the relocated backup"
        );
        assert_eq!(
            transport.last_failure_origin(0, Family::A),
            Some(0),
            "the A latest-failure origin stays with the failed resolver 0, not the current one"
        );
        assert_eq!(
            transport.last_failure_origin(0, Family::Aaaa),
            None,
            "the AAAA slot is untouched by the A failures"
        );
        transport
            .note_failure(
                &fixture_exchange(0, Family::Aaaa, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Receive,
            )
            .expect("backup AAAA failure noted");
        assert_eq!(
            transport.last_failure_origin(0, Family::Aaaa),
            Some(1),
            "a backup failure captures its own origin in the separate AAAA family slot"
        );
    }
    #[test]
    fn note_failure_unadmitted_ordinal_returns_err_and_leaves_origin_untouched() {
        let mut schedules = Schedules::new(1).unwrap();
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1"]));
        for ordinal in [ALLOWLIST_MAX, 1, usize::MAX] {
            let Err(err) = transport.note_failure(
                &fixture_exchange(ordinal, Family::A, ExchangeClass::Serving),
                &mut schedules,
                FailureReason::Connect,
            ) else {
                panic!("an unadmitted ordinal must be refused by the schedule");
            };
            assert!(
                matches!(err, crate::dns::transport::StartupDnsError::Schedule(_)),
                "the refusal must be a schedule error"
            );
        }
        assert_eq!(
            transport.last_failure_origin(1, Family::A),
            None,
            "an unadmitted ordinal must not mutate the origin table"
        );
    }
    #[test]
    fn serving_positive_emits_recovered_note_for_open_incident() {
        serving_positive_recovered_note_case(true);
    }
    #[test]
    fn serving_positive_emits_recovered_note_without_configured_set() {
        serving_positive_recovered_note_case(false);
    }
}

mod corroboration {
    use super::*;

    #[test]
    fn corroboration_latches_only_on_sustained_negative_open_with_two_resolvers() {
        // A single-resolver set has no different resolver to cross-check against,
        // so the latch is a no-op regardless of the incident state.
        let single = resolver_set_of(&["1.1.1.1"]);
        let mut transport = seeded_transport(single);
        transport.latch_corroboration(0, Family::A);
        assert_eq!(
            transport.corroboration_pending, None,
            "a single-resolver set never latches a corroboration request"
        );

        // A multi-resolver set latches on the sustained-negative open for an
        // admitted name.
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        transport.latch_corroboration(0, Family::A);
        assert_eq!(
            transport.corroboration_pending,
            Some(CorroborationPending {
                ordinal: 0,
                family: Family::A,
            }),
            "the sustained-negative open for an admitted name latches a corroboration request"
        );

        // A second open while a request is pending never stacks or overwrites.
        transport.latch_corroboration(1, Family::Aaaa);
        assert_eq!(
            transport.corroboration_pending,
            Some(CorroborationPending {
                ordinal: 0,
                family: Family::A,
            }),
            "a pending request is never overwritten or stacked"
        );
    }
    #[test]
    fn sustained_negative_open_on_the_apply_path_latches_corroboration() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let responder = spawn_responder(vec![vec![Step::NxdomainWithSoa { ttl: 300, min: 60 }]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        // Pre-seed the sustained-negative streak to just below the incident
        // threshold so this single validated NXDOMAIN opens the incident on the
        // apply path (the trigger call site).
        for _ in 0..(INCIDENT_N - 2) {
            schedules.note_negative_streak(0, 0);
        }
        schedules.note_negative_streak(0, INCIDENT_WINDOW);
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8"]));
        transport.addr = ns(responder.port());
        run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
            matches!(t, TurnResult::Published(PublishedKind::Negative))
        });
        assert_eq!(
            transport.corroboration_pending,
            Some(CorroborationPending {
                ordinal: 0,
                family: Family::A,
            }),
            "the sustained-negative open on the apply path latches a corroboration request"
        );
        drop(responder);
    }
    #[test]
    fn obsolete_negative_exchange_refuses_and_keeps_schedule_invariants() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let responder = spawn_responder(vec![vec![Step::NxdomainWithSoa { ttl: 300, min: 60 }]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let name_index = cache.name_index(0).expect("index");
        let now = 1_000_000u64;
        schedules
            .note_exchange_failure(0, Family::A, now, FailureReason::Timeout)
            .expect("seed backoff, incident, and due");
        let due_before = schedules.due_time(0, Family::A).expect("due_time");
        let due_before = due_before.expect("seeded due");
        let held = schedules.select_due(due_before).expect("select");
        let held = held.expect("held selection");
        assert_eq!(
            (held.name(), held.family()),
            (0, Family::A),
            "the seeded selection is held before the exchange starts"
        );
        let mut expected = schedules;
        expected
            .release_selection(0, Family::A)
            .expect("release the held selection on the expected copy only");
        let pair = cache
            .generations_before_query(name_index, Family::A)
            .expect("query-start pair");
        let queried_start = pair.queried;
        let other_start = pair.other;
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8"]));
        transport.addr = ns(responder.port());
        let deadline = Instant::now() + Duration::from_millis(200);
        transport
            .start_exchange(fqdn, Family::A, 0, deadline, pair, ExchangeClass::Startup)
            .expect("start obsolete exchange");
        cache
            .evict_nodata(name_index, Family::Aaaa)
            .expect("advance only the other family after start");
        let other = cache.entry(name_index, Family::Aaaa).expect("entry");
        assert_ne!(
            other.generation(),
            other_start,
            "precondition: only the other family advanced after start"
        );
        let terminal =
            run_exchange_to_terminal(&mut transport, fqdn, &mut cache, &mut schedules, deadline);
        assert!(
            matches!(terminal, TurnResult::Superseded),
            "terminal must be Superseded, never a counted failure: {terminal:?}"
        );
        let queried = cache.entry(name_index, Family::A).expect("entry");
        assert_eq!(
            queried.generation(),
            queried_start,
            "no obsolete negative is applied to the queried entry"
        );
        assert_eq!(
            schedules.due_time(0, Family::A).expect("due_time"),
            Some(due_before),
            "due and backoff are untouched by the obsolete exchange"
        );
        assert_eq!(
            schedules, expected,
            "whole-table schedule equality: due, backoff, guard, incident, streak and every other slot equal the released copy"
        );
        let at_due = schedules.select_due(due_before).expect("select at due");
        assert!(
            at_due.is_none(),
            "at the preserved due the one-second guard keeps the held family unselectable"
        );
        let reselect_now = due_before + 1;
        let reselected = schedules.select_due(reselect_now).expect("reselect");
        let reselected = reselected.expect("released by production");
        assert_eq!(
            (reselected.name(), reselected.family()),
            (0, Family::A),
            "production released the held selection at the preserved due"
        );
        drop(responder);
    }
    #[test]
    fn step_corroboration_begins_single_exchange_against_the_next_resolver() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        transport.corroboration_pending = Some(CorroborationPending {
            ordinal: 0,
            family: Family::A,
        });
        let done = transport
            .step_corroboration(&fqdn)
            .expect("corroboration begins");
        assert!(!done, "a pending request begins a corroboration");
        let corr = transport.corroboration.expect("corroboration in flight");
        assert_eq!(
            corr.target,
            active_at(2, 1),
            "the corroboration targets the next configured resolver, not the active one"
        );
        assert_eq!(
            corr.active_before,
            active_at(2, 0),
            "the active resolver at trigger time is remembered for restore"
        );
        assert_eq!(
            corr.ordinal, 0,
            "the corroboration carries the admitted name ordinal"
        );
        assert_eq!(
            corr.family,
            Family::A,
            "the corroboration carries the queried family"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(2, 1),
            "the transport relocates onto the corroboration target"
        );
        assert_eq!(
            transport.corroboration_pending, None,
            "the pending request is consumed exactly once"
        );
        assert!(
            transport.has_active_exchange(),
            "a single corroboration exchange is in flight"
        );
        assert!(
            transport
                .active
                .as_ref()
                .is_some_and(|ex| ex.class == ExchangeClass::Probe),
            "the corroboration exchange is a pure-sensor probe"
        );
        assert!(
            transport
                .active
                .as_ref()
                .is_some_and(|ex| ex.generation == Generation::INITIAL),
            "the corroboration exchange carries the initial generation so it never applies cache state"
        );
        // A second begin after the request was consumed is a no-op: the single
        // exchange is bounded and never re-begins while it is in flight.
        let done = transport.step_corroboration(&fqdn).expect("no-op");
        assert!(done, "a consumed corroboration request never re-begins");
    }
    #[test]
    fn step_corroboration_defers_while_another_exchange_or_probe_is_in_flight() {
        let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
        let mut transport = seeded_transport(set);
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        transport.corroboration_pending = Some(CorroborationPending {
            ordinal: 0,
            family: Family::A,
        });
        // A normal exchange is in flight: the corroboration defers.
        transport
            .start_exchange(
                &fqdn,
                Family::A,
                0,
                Instant::now() + Duration::from_secs(5),
                Generation::INITIAL,
                ExchangeClass::Startup,
            )
            .unwrap();
        let done = transport.step_corroboration(&fqdn).expect("defers");
        assert!(!done, "a busy transport defers the corroboration");
        assert_eq!(
            transport.corroboration_pending,
            Some(CorroborationPending {
                ordinal: 0,
                family: Family::A,
            }),
            "the pending request is preserved while another exchange is in flight"
        );
        assert_eq!(
            transport.corroboration, None,
            "no corroboration begins while the transport is busy"
        );
        // A post-window probe sweep in flight also defers the corroboration
        // (single-active guard), preserving the pending request.
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8"]));
        transport.corroboration_pending = Some(CorroborationPending {
            ordinal: 0,
            family: Family::A,
        });
        transport.probe_sweep = Some(ProbeSweep {
            remaining: [false, true, false, false, false],
            active_before: active_at(2, 0),
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(active_at(2, 1)),
        });
        let done = transport.step_corroboration(&fqdn).expect("defers");
        assert!(!done, "an in-flight probe sweep defers the corroboration");
        assert_eq!(
            transport.corroboration_pending,
            Some(CorroborationPending {
                ordinal: 0,
                family: Family::A,
            }),
            "the pending request is preserved while a probe sweep is in flight"
        );
    }
    #[test]
    fn step_corroboration_clears_pending_for_a_single_resolver_set() {
        let set = resolver_set_of(&["1.1.1.1"]);
        let mut transport = seeded_transport(set);
        let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
        transport.corroboration_pending = Some(CorroborationPending {
            ordinal: 0,
            family: Family::A,
        });
        let done = transport.step_corroboration(&fqdn).expect("clears pending");
        assert!(done, "a single-resolver set has no corroboration target");
        assert_eq!(
            transport.corroboration_pending, None,
            "the stale pending request is cleared for a single-resolver set"
        );
        assert_eq!(
            transport.corroboration, None,
            "no corroboration begins for a single-resolver set"
        );
    }
    #[test]
    fn corroboration_consistent_negative_restores_active_and_leaves_cache_unchanged() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        // Connection 1: the corroboration exchange against the target returns a
        // negative (consistent with the active resolver's negative).
        let responder = spawn_responder(vec![vec![Step::NxdomainWithSoa { ttl: 300, min: 60 }]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8"]));
        transport.resolvers = None;
        transport.corroboration = Some(Corroboration {
            target: active_at(2, 1),
            active_before: active_at(2, 0),
            ordinal: 0,
            family: Family::A,
        });
        transport.active_resolver = active_at(2, 1);
        transport.addr = ns(responder.port());
        let bindings_before = bindings_of(&cache, 0, Family::A);
        let due_before = schedules.due_time(0, Family::A).unwrap();
        let cache_before = cache;
        let schedules_before = schedules;
        let deadline = Instant::now() + Duration::from_millis(200);
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Probe,
            )
            .unwrap();
        assert!(
            matches!(
                run_exchange_to_terminal(
                    &mut transport,
                    fqdn,
                    &mut cache,
                    &mut schedules,
                    deadline
                ),
                TurnResult::Published(_)
            ),
            "the corroboration exchange publishes its outcome"
        );
        assert_eq!(
            transport.corroboration, None,
            "the corroboration concludes and clears its state"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(2, 0),
            "consistent negatives restore the active resolver with no relocation"
        );
        assert_eq!(
            transport.degradations[0],
            ResolverDegradation::default(),
            "a consistent negative never advances the active resolver's degradation"
        );
        assert_eq!(
            transport.take_dns_anomalies()[DnsAnomalyKind::CorroborationConflict.index()],
            0,
            "a consistent negative emits no conflict fact"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            bindings_before,
            "the corroboration never mutates the name cache (byte-for-byte)"
        );
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            due_before,
            "the corroboration never commits a refresh schedule"
        );
        assert_eq!(
            cache, cache_before,
            "the corroboration leaves the entire name-cache state unchanged (full-state byte-for-byte)"
        );
        assert_eq!(
            schedules, schedules_before,
            "the corroboration leaves the entire refresh-schedule state unchanged (full-state byte-for-byte)"
        );
        // The concluded corroboration never re-begins: no pending request remains
        // and a later begin is a no-op (bounded single exchange, no retries).
        let done = transport
            .step_corroboration(fqdn)
            .expect("no-op after conclusion");
        assert!(done, "a concluded corroboration never re-begins");
        drop(responder);
    }
    #[test]
    fn corroboration_conflict_advances_degradation_and_relocates_when_degraded() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        // Connection 1: the corroboration exchange against the target returns a
        // positive with eligible bindings while the active resolver returned a
        // negative — a conflict.
        let responder = spawn_responder(vec![vec![Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        }]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]));
        transport.resolvers = None;
        transport.corroboration = Some(Corroboration {
            target: active_at(3, 1),
            active_before: active_at(3, 0),
            ordinal: 0,
            family: Family::A,
        });
        transport.active_resolver = active_at(3, 1);
        // The active resolver is two failures from degraded; the conflict advance
        // crosses the threshold and relocates to the next healthy resolver.
        transport.degradations[0] = ResolverDegradation::Healthy { consecutive: 2 };
        transport.addr = ns(responder.port());
        let cache_before = cache;
        let schedules_before = schedules;
        let deadline = Instant::now() + Duration::from_millis(200);
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Probe,
            )
            .unwrap();
        assert!(
            matches!(
                run_exchange_to_terminal(
                    &mut transport,
                    fqdn,
                    &mut cache,
                    &mut schedules,
                    deadline
                ),
                TurnResult::Published(_)
            ),
            "the corroboration exchange publishes its outcome"
        );
        assert_eq!(
            transport.take_dns_anomalies()[DnsAnomalyKind::CorroborationConflict.index()],
            1,
            "a positive/negative conflict emits exactly one distinct conflict fact"
        );
        assert_eq!(
            transport.degradations[0],
            ResolverDegradation::Degraded,
            "the conflict advance crosses the degraded threshold"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(3, 1),
            "a degraded active resolver relocates to the next healthy resolver"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            1,
            "the degraded enter crossing is emitted exactly once"
        );
        assert_eq!(
            transport.corroboration, None,
            "the corroboration concludes and clears its state"
        );
        assert_eq!(
            cache, cache_before,
            "a conflict corroboration leaves the entire name-cache state unchanged (full-state byte-for-byte)"
        );
        assert_eq!(
            schedules, schedules_before,
            "a conflict corroboration leaves the entire refresh-schedule state unchanged (full-state byte-for-byte)"
        );
        drop(responder);
    }
    #[test]
    fn corroboration_conflict_below_threshold_advances_without_relocating() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let responder = spawn_responder(vec![vec![Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        }]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = seeded_transport(resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]));
        transport.resolvers = None;
        transport.corroboration = Some(Corroboration {
            target: active_at(3, 1),
            active_before: active_at(3, 0),
            ordinal: 0,
            family: Family::A,
        });
        transport.active_resolver = active_at(3, 1);
        transport.addr = ns(responder.port());
        let cache_before = cache;
        let schedules_before = schedules;
        let deadline = Instant::now() + Duration::from_millis(200);
        transport
            .start_exchange(
                fqdn,
                Family::A,
                0,
                deadline,
                Generation::INITIAL,
                ExchangeClass::Probe,
            )
            .unwrap();
        assert!(
            matches!(
                run_exchange_to_terminal(
                    &mut transport,
                    fqdn,
                    &mut cache,
                    &mut schedules,
                    deadline
                ),
                TurnResult::Published(_)
            ),
            "the corroboration exchange publishes its outcome"
        );
        assert_eq!(
            transport.take_dns_anomalies()[DnsAnomalyKind::CorroborationConflict.index()],
            1,
            "a positive/negative conflict emits exactly one distinct conflict fact"
        );
        assert_eq!(
            transport.degradations[0],
            ResolverDegradation::Healthy { consecutive: 1 },
            "a below-threshold conflict advances the degradation by exactly one"
        );
        assert_eq!(
            transport.active_resolver,
            active_at(3, 0),
            "a below-threshold advance leaves the active resolver in place"
        );
        assert_eq!(
            transport.take_resolver_transitions(),
            0,
            "no degraded crossing below the threshold"
        );
        assert_eq!(
            cache, cache_before,
            "a conflict corroboration leaves the entire name-cache state unchanged (full-state byte-for-byte)"
        );
        assert_eq!(
            schedules, schedules_before,
            "a conflict corroboration leaves the entire refresh-schedule state unchanged (full-state byte-for-byte)"
        );
        drop(responder);
    }
}

mod turn_result {
    use super::*;

    #[test]
    fn turn_result_carries_published_kind_structurally() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();

        // Each sub-case owns its transport in a nested block so the fixed-profile
        // transport (a ~144 KiB struct) never accumulates several live copies on
        // the test thread's stack at once.
        {
            // A valid positive A publishes ResolvedPositive.
            let positive = spawn_responder(vec![vec![Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            }]]);
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(positive.port());
            transport.now0 = 1_000_000;
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                *t == TurnResult::Published(PublishedKind::ResolvedPositive)
            });
            drop(positive);
        }

        {
            // An all-ineligible positive publishes NoEligible.
            let ineligible = spawn_responder(vec![vec![Step::PositiveA {
                ttl: 120,
                octets: [10, 0, 0, 1],
            }]]);
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(ineligible.port());
            transport.now0 = 1_000_000;
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                *t == TurnResult::Published(PublishedKind::NoEligible)
            });
            drop(ineligible);
        }

        {
            // A validated NXDOMAIN publishes Negative.
            let negative = spawn_responder(vec![vec![Step::NxdomainWithSoa { ttl: 300, min: 60 }]]);
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(negative.port());
            transport.now0 = 1_000_000;
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                *t == TurnResult::Published(PublishedKind::Negative)
            });
            drop(negative);
        }
    }
    #[test]
    fn turn_result_carries_failure_reason_structurally() {
        let cfg = config();
        let fqdn = cfg.allowlist().get(0).unwrap();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();

        // Each sub-case owns its transport in a nested block so the fixed-profile
        // transport (a ~144 KiB struct) never accumulates several live copies on
        // the test thread's stack at once.
        {
            // A refused connect fails with Connect.
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
            let dead_port = probe.local_addr().expect("probe addr").port();
            drop(probe);
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(dead_port);
            transport.now0 = 1_000_000;
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                *t == TurnResult::Failed(FailureReason::Connect)
            });
        }

        {
            // A silent peer times out.
            let silent =
                spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(silent.port());
            transport.now0 = 1_000_000;
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                *t == TurnResult::Failed(FailureReason::Timeout)
            });
            drop(silent);
        }

        {
            // A malformed response fails with Receive.
            let malformed = spawn_responder(vec![vec![Step::Malformed(vec![1, 2, 3, 4])]]);
            let mut transport = StartupDns::new().unwrap();
            transport.addr = ns(malformed.port());
            transport.now0 = 1_000_000;
            run_exchange_expecting(&mut transport, fqdn, &mut cache, &mut schedules, |t| {
                *t == TurnResult::Failed(FailureReason::Receive)
            });
            drop(malformed);
        }
    }
    /// Construction boundary with the derived-only routes: every route keeps
    /// `index < set_len` and `set_len` in `1..=MAX_RESOLVERS` (the length travels
    /// only from a validated non-empty [`ResolverSet`] or the fixed singleton
    /// seat, never from a caller-supplied scalar), so an active resolver cannot
    /// point past the fixed `MAX_RESOLVERS` arrays. The selected-index route is
    /// fallible: `None` for an index equal to the set length or an out-of-range
    /// index (including `usize::MAX`) — never a partial value and never a panic.
    #[test]
    fn active_resolver_construction_boundary() {
        let sets = [
            resolver_set_of(&["1.1.1.1"]),
            resolver_set_of(&["1.1.1.1", "2.2.2.2"]),
            resolver_set_of(&["1.1.1.1", "2.2.2.2", "3.3.3.3"]),
            resolver_set_of(&["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]),
            resolver_set_of(&["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]),
        ];
        for (len, set) in sets.into_iter().enumerate().map(|(i, s)| (i + 1, s)) {
            assert_eq!(
                ActiveResolver::primary_of(&set),
                ActiveResolver {
                    index: 0,
                    set_len: len
                }
            );
            for index in 0..len {
                let Some(active) = ActiveResolver::primary_of(&set).with_index(index) else {
                    panic!("in-range index {index} of a {len}-resolver set must be a candidate");
                };
                assert_eq!(
                    active,
                    ActiveResolver {
                        index,
                        set_len: len
                    }
                );
            }
            assert_eq!(
                ActiveResolver::primary_of(&set).with_index(len),
                None,
                "index equal to the set length is out of range"
            );
            assert_eq!(
                ActiveResolver::primary_of(&set).with_index(usize::MAX),
                None,
                "an out-of-range selected index is no candidate"
            );
        }
        assert_eq!(
            ActiveResolver::singleton(),
            ActiveResolver {
                index: 0,
                set_len: 1
            }
        );
        let last_backup =
            ActiveResolver::primary_of(&resolver_set_of(&["1.1.1.1", "2.2.2.2", "3.3.3.3"]))
                .with_index(2)
                .expect("the last configured resolver is a valid backup");
        assert_eq!(
            last_backup,
            ActiveResolver {
                index: 2,
                set_len: 3
            }
        );
        assert_eq!(
            last_backup.to_primary(),
            ActiveResolver {
                index: 0,
                set_len: 3
            }
        );
    }
}

/// Axis-A retention: `start_exchange` retains the query-start snapshot for
/// both families immutably on the active exchange; the captured pair comes
/// from the one Cache-owned capture helper shared with production startup
/// and serving, and this witness checks both captured tags against the live
/// cache, then moves the non-queried family after the exchange begins
/// (docs/alumina-proxy.md:119).
#[test]
fn snapshot_retains_other_family_generation_after_start() {
    let mut cache = Cache::new(2).unwrap();
    let name_index = cache.name_index(0).unwrap();
    cache.evict_nodata(name_index, Family::A).unwrap();
    cache.evict_nodata(name_index, Family::Aaaa).unwrap();
    cache.evict_nodata(name_index, Family::Aaaa).unwrap();
    let pair = cache
        .generations_before_query(name_index, Family::A)
        .unwrap();
    assert_ne!(
        pair.queried, pair.other,
        "seed unequal non-INITIAL families so a swapped capture cannot pass"
    );
    let queried_now = cache.entry(name_index, Family::A).unwrap().generation();
    let other_now = cache.entry(name_index, Family::Aaaa).unwrap().generation();
    assert_eq!(
        pair.queried, queried_now,
        "capture maps queried to the A entry"
    );
    assert_eq!(
        pair.other, other_now,
        "capture maps other to the AAAA entry"
    );
    let reverse = cache
        .generations_before_query(name_index, Family::Aaaa)
        .unwrap();
    assert_ne!(
        reverse.queried, reverse.other,
        "reverse direction also witnesses unequal A/AAAA tags"
    );
    assert_eq!(
        reverse.queried, other_now,
        "reverse capture maps queried to the AAAA entry"
    );
    assert_eq!(
        reverse.other, queried_now,
        "reverse capture maps other to the A entry"
    );
    let deadline = Instant::now() + Duration::from_millis(200);
    let cfg = config();
    let fqdn = cfg.allowlist().get(0).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(9);
    transport.now0 = 1_000_000;
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, pair, ExchangeClass::Startup)
        .unwrap();
    assert_eq!(
        transport.active.as_ref().unwrap().other_generation,
        pair.other,
        "start must retain the query-start other-family generation"
    );
    cache.evict_nodata(name_index, Family::Aaaa).unwrap();
    let moved = cache.entry(name_index, Family::Aaaa).unwrap().generation();
    assert_ne!(
        moved, pair.other,
        "precondition: the NODATA eviction must advance the other family"
    );
    assert_eq!(
        transport.active.as_ref().unwrap().other_generation,
        pair.other,
        "snapshot is immutable: re-read active after mutation retains the other tag"
    );
}

#[test]
fn resolve_window_first_failure_warns_with_live_context() {
    use crate::dns::cache::evidence::{Evidence, ResolverSource};
    let cfg = config();
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let floor = transport.now_u64();
    let idx = cache.name_index(0).unwrap();
    cache
        .evict_nodata_evidenced(
            idx,
            Family::A,
            Evidence::new(
                false,
                true,
                false,
                ResolverSource::index(1).unwrap(),
                Some(600),
                floor,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        cache
            .negative_projection(idx, Family::A, floor)
            .unwrap()
            .is_some()
    );
    let dead = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = std::env::temp_dir().join(format!("alumina-l39-{}.log", std::process::id()));
    let sink = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut logs = crate::log::LogStore::with_fd(&sink).unwrap();
    transport
        .resolve_window(
            WindowInputs {
                config: &cfg,
                cache: &mut cache,
                schedules: &mut schedules,
                nameserver: ns(dead),
                now0: floor,
                window: Duration::from_secs(2),
            },
            &mut logs,
        )
        .unwrap();
    drop(logs);
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let _ = std::fs::remove_file(&path);
    assert_eq!(text.matches("kind=startup_warning").count(), 1, "{text}");
    assert!(
        text.contains("kind=startup_warning")
            && text.contains("reason=\"connect\"")
            && text.contains("family=A")
            && text.contains("context=\"a\""),
        "{text}"
    );
}

#[test]
fn startup_ledger_current_cache_refresh_overwrites_sticky_resolved() {
    use crate::dns::cache::StagedPositive;
    use crate::dns::cache::evidence::{AssuranceRequirement, Evidence, ResolverSource};
    use crate::eligibility::NumericAddr;
    let mut ledger = WindowLedger::new(1);
    let mut cache =
        Cache::with_requirement(1, AssuranceRequirement::ResolverAuthenticated).unwrap();
    let name = cache.name_index(0).unwrap();
    let evidence = Evidence::new(
        false,
        true,
        false,
        ResolverSource::index(0).unwrap(),
        Some(60),
        1000,
    )
    .unwrap();
    let staged = StagedPositive::stage_with_evidence(
        name,
        Family::A,
        Generation::INITIAL,
        &[NumericAddr::V4([8, 8, 8, 8].into())],
        1001,
        60,
        Some(evidence),
    )
    .unwrap();
    cache.publish_positive(&staged).unwrap();
    ledger.mark_published(0, Family::A, PublishedKind::ResolvedPositive);
    assert!(
        !ledger.is_resolved(0),
        "a published positive alone is not resolution authority; the refresh must establish it"
    );
    ledger.refresh_resolved(&cache, 1001).unwrap();
    assert!(ledger.is_resolved(0), "Auth proof valid at its receipt");
    assert!(
        cache.entry(name, Family::A).unwrap().servable(1060),
        "the ordinary binding is still fresh at 1060"
    );
    ledger.refresh_resolved(&cache, 1060).unwrap();
    assert!(
        !ledger.is_resolved(0),
        "an expired Auth proof must not lease resolved status while the binding is fresh"
    );
    assert_eq!(ledger.exchanges, 1, "refresh must not re-count exchanges");
    assert_eq!(ledger.failed, 0, "refresh must not count failures");
    assert!(
        ledger.first_failure.is_none(),
        "refresh must not record failures"
    );
    let report = ledger.finish();
    assert_eq!(
        report.resolved_names, 0,
        "the expired proof is not resolved"
    );
    assert_eq!(
        report.outcomes[0],
        NameOutcome::PositiveUnusable,
        "an expired positive is reported positive-unusable, not resolved"
    );
    ledger.mark_failed(0, Family::A, FailureReason::Timeout);
    assert_eq!(ledger.failed, 1, "the Timeout failure is counted");
    assert_eq!(
        ledger.first_failure,
        Some((0, Family::A)),
        "the Timeout failure records the first failure"
    );
    let report = ledger.finish();
    assert_eq!(
        report.outcomes[0],
        NameOutcome::Failed(FailureReason::Timeout),
        "a later Timeout overrides the historical positive"
    );
    ledger.refresh_resolved(&cache, 1001).unwrap();
    assert!(ledger.is_resolved(0), "usable again at 1001");
    ledger.mark_failed(0, Family::A, FailureReason::Timeout);
    let report = ledger.finish();
    assert_eq!(
        report.outcomes[0],
        NameOutcome::Resolved,
        "a currently usable name stays resolved despite the failed exchange"
    );
    assert_eq!(
        report.family_results[0][0],
        Some(Err(FailureReason::Timeout))
    );
}

#[test]
fn startup_refresh_error_atomic_preserves_prior_mask() {
    use crate::dns::cache::CacheError;
    use crate::dns::cache::StagedPositive;
    use crate::dns::cache::evidence::{AssuranceRequirement, Evidence, ResolverSource};
    use crate::eligibility::NumericAddr;
    let mut ledger = WindowLedger::new(2);
    ledger.resolved[0] = true;
    ledger.resolved[1] = true;
    assert!(
        ledger.is_resolved(0) && ledger.is_resolved(1),
        "the prior mask starts with both names resolved"
    );
    let mut cache =
        Cache::with_requirement(1, AssuranceRequirement::ResolverAuthenticated).unwrap();
    let name = cache.name_index(0).unwrap();
    let evidence = Evidence::new(
        false,
        true,
        false,
        ResolverSource::index(0).unwrap(),
        Some(60),
        1000,
    )
    .unwrap();
    let staged = StagedPositive::stage_with_evidence(
        name,
        Family::A,
        Generation::INITIAL,
        &[NumericAddr::V4([8, 8, 8, 8].into())],
        1001,
        60,
        Some(evidence),
    )
    .unwrap();
    cache.publish_positive(&staged).unwrap();
    let err = ledger.refresh_resolved(&cache, 1060).unwrap_err();
    assert_eq!(
        err,
        CacheError::NameOutOfRange,
        "a ledger wider than the cache errors on the out-of-range ordinal"
    );
    assert!(
        ledger.is_resolved(0) && ledger.is_resolved(1),
        "a failed refresh publishes no partial snapshot; the prior mask is unchanged"
    );
    assert_eq!(ledger.exchanges, 0, "refresh errors touch no counters");
    assert_eq!(ledger.failed, 0, "refresh errors touch no counters");
    assert!(
        ledger.first_failure.is_none(),
        "refresh errors touch no counters"
    );
}

fn zero_window_report(cache: &mut Cache, now0: u64) -> (StartupReport, u64) {
    let cfg = config();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    let mut logs = crate::log::LogStore::with_fd(&sink).unwrap();
    transport
        .resolve_window(
            WindowInputs {
                config: &cfg,
                cache,
                schedules: &mut schedules,
                nameserver: ns(1),
                now0,
                window: Duration::ZERO,
            },
            &mut logs,
        )
        .unwrap()
}

#[test]
fn zero_window_reports_current_cache_admission_without_exchange() {
    use crate::dns::cache::StagedPositive;
    use crate::dns::cache::evidence::{AssuranceRequirement, Evidence, ResolverSource};
    use crate::eligibility::NumericAddr;
    let now0: u64 = 1_000_000;
    let mut cache =
        Cache::with_requirement(2, AssuranceRequirement::ResolverAuthenticated).unwrap();
    let name = cache.name_index(0).unwrap();
    let evidence = Evidence::new(
        false,
        true,
        false,
        ResolverSource::index(0).unwrap(),
        Some(600),
        now0,
    )
    .unwrap();
    let staged = StagedPositive::stage_with_evidence(
        name,
        Family::A,
        Generation::INITIAL,
        &[NumericAddr::V4([8, 8, 8, 8].into())],
        now0 + 1,
        600,
        Some(evidence),
    )
    .unwrap();
    cache.publish_positive(&staged).unwrap();
    let (report, elapsed) = zero_window_report(&mut cache, now0);
    assert_eq!(
        report.resolved_names, 1,
        "owner-admissible name resolves from cache state even with a zero-length window"
    );
    assert_eq!(
        report.outcomes[0],
        NameOutcome::Resolved,
        "the admissible name is reported resolved"
    );
    assert_eq!(
        elapsed, 0,
        "the zero-length window anchors readiness at its own start"
    );
    assert_eq!(
        report.exchanges, 0,
        "the admissible zero-length window runs no exchange"
    );

    let lapsed_floor = now0.saturating_sub(2_000);
    let lapsed_ttl = 60u64;
    let lapsed_receipt = now0.saturating_sub(30);
    let mut lapsed =
        Cache::with_requirement(2, AssuranceRequirement::ResolverAuthenticated).unwrap();
    let lapsed_name = lapsed.name_index(0).unwrap();
    let stale = Evidence::new(
        false,
        true,
        false,
        ResolverSource::index(0).unwrap(),
        Some(u32::try_from(lapsed_ttl).unwrap()),
        lapsed_floor,
    )
    .unwrap();
    let staged = StagedPositive::stage_with_evidence(
        lapsed_name,
        Family::A,
        Generation::INITIAL,
        &[NumericAddr::V4([8, 8, 8, 8].into())],
        lapsed_receipt,
        lapsed_ttl,
        Some(stale),
    )
    .unwrap();
    lapsed.publish_positive(&staged).unwrap();
    let (report, elapsed) = zero_window_report(&mut lapsed, now0);
    let anchor = now0.saturating_add(elapsed);
    assert!(
        lapsed_receipt + lapsed_ttl > anchor,
        "the binding is still fresh at the returned decision anchor"
    );
    assert!(
        lapsed_floor + lapsed_ttl <= anchor,
        "the proof has already expired at the returned decision anchor"
    );
    assert_eq!(
        report.exchanges, 0,
        "the expired-proof zero-length window runs no exchange"
    );
    assert_eq!(
        report.resolved_names, 0,
        "an expired proof with a still-fresh binding must not resolve"
    );
}

#[test]
fn actual_transport_publication_callbacks_share_one_instant_and_owner_second() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use crate::dns::publication::ObservationPhase;
            use crate::runtime::tunnel::WorkerClock;

            let responder = spawn_bounded_responder(vec![vec![Step::PositiveAAd {
                ttl: 60,
                octets: [9, 9, 9, 9],
            }]]);
            let config = config();
            let mut cache = Cache::for_config(&config).unwrap();
            let mut schedules = Schedules::new(config.allowlist().len()).unwrap();
            let mut transport = StartupDns::new().unwrap();
            let peer = SocketAddr::from(([127, 0, 0, 1], responder.port()));
            transport
                .begin_window(peer, *config.resolver_set(), 1000, Duration::ZERO)
                .unwrap();
            let clock = WorkerClock::new(transport.window_start(), 1000);
            let name = cache.name_index(0).unwrap();
            let pair = cache.generations_before_query(name, Family::A).unwrap();
            let fqdn = config.allowlist().get(0).unwrap();
            let started = Instant::now();
            let deadline = started + Duration::from_secs(5);
            transport
                .start_exchange(fqdn, Family::A, 0, deadline, pair, ExchangeClass::Serving)
                .unwrap();
            let mut observations = [None, None];
            let mut count = 0;
            let mut observer = |phase, _cache: &Cache, _name, secs, instant| {
                observations[count] = Some((phase, secs, instant));
                count += 1;
            };
            loop {
                match transport
                    .advance_exchange_observed(fqdn, &mut cache, &mut schedules, &mut observer)
                    .unwrap()
                {
                    TurnResult::Pending => {
                        transport.wait_dns_readiness(deadline).unwrap();
                    }
                    TurnResult::Published(_) => break,
                    other => panic!("publication failed: {other:?}"),
                }
            }
            let returned = Instant::now();
            assert_eq!(count, 2);
            let (before_phase, before_secs, before) = observations[0].unwrap();
            let (after_phase, after_secs, after) = observations[1].unwrap();
            assert_eq!(before_phase, ObservationPhase::BeforeCommit);
            assert_eq!(after_phase, ObservationPhase::AfterCommit);
            assert_eq!(before, after);
            assert!(started <= before && after <= returned);
            assert_eq!(before_secs, after_secs);
            assert_eq!(before_secs, clock.cache_secs(before));
            responder.finish().unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn responder_preconnect_panic_is_bounded_and_preserved() {
    let responder = spawn_bounded_responder(vec![vec![Step::PositiveA {
        ttl: 60,
        octets: [9, 9, 9, 9],
    }]]);
    let peer = SocketAddr::from(([127, 0, 0, 1], responder.port()));
    let (done, cancelled) = std::sync::mpsc::channel();
    let fallback = thread::spawn(move || {
        if cancelled.recv_timeout(Duration::from_secs(2)).is_err() {
            let _ = TcpStream::connect_timeout(&peer, Duration::from_millis(200));
        }
    });
    let started = Instant::now();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _responder = responder;
        panic!("original preconnect failure");
    }));
    let elapsed = started.elapsed();
    let _ = done.send(());
    fallback.join().unwrap();
    let panic = failure.expect_err("preconnect failure must not become success");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"original preconnect failure")
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "teardown took {elapsed:?}"
    );
}

#[test]
fn bounded_responder_joins_an_incomplete_query() {
    let responder = spawn_bounded_responder(vec![vec![Step::PositiveA {
        ttl: 60,
        octets: [9, 9, 9, 9],
    }]]);
    let accepted = Arc::clone(&responder.responder.as_ref().unwrap().connections);
    let peer = SocketAddr::from(([127, 0, 0, 1], responder.port()));
    let mut client = TcpStream::connect(peer).unwrap();
    client.write_all(&[0, 10]).unwrap();
    for _ in 0..40 {
        if accepted.load(Ordering::Acquire) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    responder.finish().unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
}

#[test]
fn bounded_responder_interrupts_a_delayed_reply() {
    let responder =
        spawn_bounded_responder(vec![vec![Step::Stall(Duration::from_secs(2)), Step::Close]]);
    let accepted = Arc::clone(&responder.responder.as_ref().unwrap().connections);
    let peer = SocketAddr::from(([127, 0, 0, 1], responder.port()));
    let _client = TcpStream::connect(peer).unwrap();
    for _ in 0..40 {
        if accepted.load(Ordering::Acquire) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    responder.finish().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn bounded_responder_finish_exposes_worker_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let responder = Responder {
        addr: listener.local_addr().unwrap(),
        handle: Some(thread::spawn(|| panic!("responder failure"))),
        connections: Arc::new(AtomicUsize::new(0)),
        closed_after_prefix: Arc::new(AtomicUsize::new(0)),
    };
    let bounded = BoundedResponder {
        responder: Some(responder),
        cancel: Arc::new(ResponderCancellation {
            requested: AtomicBool::new(false),
            active: Mutex::new(None),
        }),
    };
    let panic = bounded
        .finish()
        .expect_err("worker failure must be observable");
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"responder failure"));
}
