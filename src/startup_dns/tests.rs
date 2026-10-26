use super::*;
use crate::config::parse_config_document;
use crate::enforcement::monitor::DnsAnomalyKind;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

enum Step {
    PositiveA {
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

struct Responder {
    addr: SocketAddr,
    handle: Option<thread::JoinHandle<()>>,
    connections: Arc<AtomicUsize>,
    closed_after_prefix: Arc<AtomicUsize>,
}

impl Responder {
    fn port(&self) -> u16 {
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

fn respond_for(query: &[u8], step: &Step) -> Option<Vec<u8>> {
    let tid = u16::from_be_bytes([query[0], query[1]]);
    let qname = &query[12..query.len() - 4];
    let question = question_from(query);
    let mut msg = Vec::new();
    msg.extend_from_slice(&tid.to_be_bytes());
    let (rcode, an, ns, answers, authority): (u16, u16, u16, Vec<Vec<u8>>, Vec<Vec<u8>>) =
        match step {
            Step::PositiveA { ttl, octets } | Step::PositiveAMismatchedTid { ttl, octets } => {
                (0, 1, 0, vec![record(qname, 1, *ttl, octets)], vec![])
            }
            Step::PositiveAaaa { ttl, octets } => {
                (0, 1, 0, vec![record(qname, 28, *ttl, octets)], vec![])
            }
            Step::NodataWithSoa { ttl, min } => {
                let soa = soa_rdata("example.org", *min);
                let owner = qname_bytes("example.org");
                (0, 0, 1, vec![], vec![record(&owner, 6, *ttl, &soa)])
            }
            Step::NxdomainWithSoa { ttl, min } => {
                let soa = soa_rdata("example.org", *min);
                let owner = qname_bytes("example.org");
                (3, 0, 1, vec![], vec![record(&owner, 6, *ttl, &soa)])
            }
            Step::BailiwickViolationCname { ttl } => (
                0,
                1,
                0,
                vec![record(qname, 5, *ttl, &qname_bytes("evil.com"))],
                vec![],
            ),
            Step::Stall(_)
            | Step::Malformed(_)
            | Step::LengthPrefixOnly { .. }
            | Step::FragmentedPositive { .. }
            | Step::Close => {
                return None;
            }
        };
    let flags = 0x8000 | rcode;
    msg.extend_from_slice(&flags.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&an.to_be_bytes());
    msg.extend_from_slice(&ns.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&question);
    for rec in answers {
        msg.extend_from_slice(&rec);
    }
    for rec in authority {
        msg.extend_from_slice(&rec);
    }
    Some(msg)
}

#[expect(
    clippy::too_many_lines,
    reason = "test harness dispatches one arm per wire behaviour; the length-prefix probe arm keeps it over the heuristic line budget"
)]
fn spawn_responder(conn_scripts: Vec<Vec<Step>>) -> Responder {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
    let addr = listener.local_addr().expect("responder addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let connections_thread = Arc::clone(&connections);
    let closed_after_prefix = Arc::new(AtomicUsize::new(0));
    let closed_after_prefix_thread = Arc::clone(&closed_after_prefix);
    let handle = thread::spawn(move || {
        let scripts = conn_scripts.into_iter();
        for conn_steps in scripts {
            let Ok((mut sock, _)) = listener.accept() else {
                break;
            };
            connections_thread.fetch_add(1, Ordering::Relaxed);
            for step in conn_steps {
                match step {
                    Step::Stall(d) => thread::sleep(d),
                    Step::Close => break,
                    Step::Malformed(bytes) => {
                        let mut lenb = [0u8; 2];
                        if read_exact(&mut sock, &mut lenb).is_err() {
                            break;
                        }
                        let qlen = usize::from(u16::from_be_bytes(lenb));
                        let mut q = vec![0u8; qlen];
                        if qlen == 0 || read_exact(&mut sock, &mut q).is_err() {
                            break;
                        }
                        let mut out = Vec::with_capacity(bytes.len() + 2);
                        out.extend_from_slice(
                            &u16::try_from(bytes.len())
                                .expect("reply fits u16 wire length")
                                .to_be_bytes(),
                        );
                        out.extend_from_slice(&bytes);
                        if sock.write_all(&out).is_err() {
                            break;
                        }
                    }
                    Step::LengthPrefixOnly { len } => {
                        let mut lenb = [0u8; 2];
                        if read_exact(&mut sock, &mut lenb).is_err() {
                            break;
                        }
                        let qlen = usize::from(u16::from_be_bytes(lenb));
                        let mut q = vec![0u8; qlen];
                        if qlen == 0 || read_exact(&mut sock, &mut q).is_err() {
                            break;
                        }
                        // Write only the 2-byte length prefix, then probe: the
                        // length-prefix guard must close the connection right
                        // after the prefix, before any body read or parse. A
                        // removed guard would instead keep the connection open
                        // waiting for the never-sent body until the deadline.
                        if sock.write_all(&len.to_be_bytes()).is_err() {
                            break;
                        }
                        let _ = sock.set_read_timeout(Some(Duration::from_millis(400)));
                        let mut probe = [0u8; 1];
                        if matches!(sock.read(&mut probe), Ok(0)) {
                            closed_after_prefix_thread.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Step::FragmentedPositive {
                        ttl,
                        octets,
                        chunk,
                        gap,
                    } => {
                        let Some(q) = read_query(&mut sock) else {
                            break;
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
                                thread::sleep(gap);
                            }
                        }
                    }
                    step => {
                        let Some(q) = read_query(&mut sock) else {
                            break;
                        };
                        let reply = respond_for(&q, &step);
                        if let Some(mut bytes) = reply {
                            if matches!(step, Step::PositiveAMismatchedTid { .. }) {
                                let mismatched =
                                    u16::from_be_bytes([bytes[0], bytes[1]]).wrapping_add(1);
                                bytes[0] = (mismatched >> 8) as u8;
                                bytes[1] =
                                    u8::try_from(mismatched & 0xff).expect("dns tid low byte");
                            }
                            let mut out = Vec::with_capacity(bytes.len() + 2);
                            out.extend_from_slice(
                                &u16::try_from(bytes.len())
                                    .expect("reply fits u16 wire length")
                                    .to_be_bytes(),
                            );
                            out.extend_from_slice(&bytes);
                            if sock.write_all(&out).is_err() {
                                break;
                            }
                        }
                    }
                }
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
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n[allowed_fqdn.\"beta.example.org:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n",
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
        matches!(err, StartupDnsError::Dns(dns::DnsError::Cache(_))),
        "storage refusal surfaces as Dns(Cache): {err:?}"
    );
}

#[test]
fn extreme_ttl_positive_is_counted_as_a_dns_anomaly() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: dns::EXTREME_TTL_THRESHOLD + 1,
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
        [0, 0, 0],
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
        [0, 0, 0],
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
    let outcome = dns::Outcome::Positive {
        family: Family::A,
        bindings: dns::BindingList::from_slice(&[crate::eligibility::NumericAddr::V4(
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

#[test]
fn cooperative_silent_peer_yields_pending_before_deadline() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(400);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
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
    let responder = spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(400);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
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
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
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
fn stale_generation_is_refused_at_apply() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: 120,
            octets: [1, 1, 1, 1],
        },
        Step::Close,
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
    let name_index = cache.name_index(0).unwrap();
    let captured = cache.entry(name_index, Family::A).unwrap().generation();
    assert_eq!(captured, Generation::INITIAL);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, captured)
        .unwrap();
    // Bump the cache entry generation while the exchange is in flight so the
    // generation captured at start is stale when the response is applied.
    let staged = crate::cache::StagedPositive::stage(
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
    let mut result = None;
    for _ in 0..256 {
        match transport.advance_exchange(fqdn, &mut cache, &mut schedules) {
            Ok(TurnResult::Pending) => {
                if transport
                    .exchange_deadline()
                    .is_some_and(|d| Instant::now() >= d)
                {
                    continue;
                }
                let _ = transport.wait_dns_readiness(deadline).unwrap();
            }
            Ok(term) => {
                result = Some(Ok(term));
                break;
            }
            Err(err) => {
                result = Some(Err(err));
                break;
            }
        }
    }
    assert!(
        matches!(
            result,
            Some(Err(StartupDnsError::Dns(DnsError::Cache(
                CacheError::StaleGeneration
            ))))
        ),
        "an obsolete captured generation must refuse apply, got {result:?}"
    );
    drop(responder);
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
    use crate::serve::{ServeStorage, StartupDecision};

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
    let mut storage = ServeStorage::boot(&cfg).expect("boot storage outside the measured window");

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
        matches!(outcome.decision, StartupDecision::Exit75 { .. }),
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
            .start_exchange(fqdn0, Family::A, 0, deadline, Generation::INITIAL)
            .unwrap();
        let err = transport
            .start_exchange(fqdn1, Family::A, 1, deadline, Generation::INITIAL)
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
            .start_exchange(fqdn0, Family::A, 0, deadline, Generation::INITIAL)
            .unwrap();
        let err = transport
            .start_exchange(fqdn1, Family::A, 1, deadline, Generation::INITIAL)
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
fn cooperative_turn_performs_zero_blocking_polls() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
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
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
        .unwrap();
    transport.arm_write(WriteForce::Partial(1));
    let mut guard = 0;
    loop {
        match transport.active_step() {
            Some(ExchangeStep::Connecting) => {
                assert!(matches!(
                    transport
                        .advance_exchange(fqdn, &mut cache, &mut schedules)
                        .unwrap(),
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
        transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap(),
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
        transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap(),
        TurnResult::Pending
    ));
    let before = transport.poll_ticks;
    let _ = transport.wait_dns_readiness(deadline).unwrap();
    assert!(
        transport.poll_ticks > before,
        "after an actual sending WouldBlock the owner wait must perform a \
         real poll (awaiting-writable), not an instant-returning busy loop"
    );
    let mut result = None;
    for _ in 0..200 {
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
        "a valid response must publish after an awaited would-block send, got {result:?}"
    );
    assert_ne!(bindings_of(&cache, 0, Family::A), []);
    drop(responder);
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
    let generation = cache.entry(name_index, Family::A).unwrap().generation();
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, generation)
        .unwrap();
    let terminal = run_exchange_to_terminal(transport, fqdn, cache, schedules, deadline);
    assert!(
        expect(&terminal),
        "the exchange must conclude as expected, got {terminal:?}"
    );
}

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
            .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
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
    transport.bailiwick = BailiwickZones::from_allowlist(cfg.allowlist(), cfg.cname_bailiwick())
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
            len: u16::try_from(DNS_MSG_LIMIT + 1).expect("oversized prefix fits u16 wire length"),
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
            .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
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

/// Builds a configured resolver set from numeric address strings for the pure
/// failover/failback state-machine tests (loopback dialing is impossible:
/// `Nameserver` fixes the port at 53, and the relay would reach a real host).
fn resolver_set_of(addrs: &[&str]) -> ResolverSet {
    let mut entries = [crate::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
    for (slot, addr) in addrs.iter().enumerate() {
        entries[slot] = crate::resolver::select(addr).expect("ns");
    }
    ResolverSet::from_slice(&entries[..addrs.len()]).expect("resolver count fits")
}

/// A transport seated onto a configured resolver set with the primary active,
/// as [`StartupDns::begin_window`] leaves it: the primary is recorded as
/// exercised by the startup window.
fn seeded_transport(set: ResolverSet) -> StartupDns {
    let mut transport = StartupDns::new().unwrap();
    transport.resolvers = Some(set);
    transport.active_resolver = ActiveResolver::primary(set.len());
    transport.window_exercised[0] = true;
    transport.now0 = 1_000_000;
    transport
}

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
        let mut entries = [crate::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
        entries[0] = crate::resolver::select("1.1.1.1#dns.google").expect("dot ns");
        entries[1] = crate::resolver::select("8.8.8.8").expect("plain ns");
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
        let mut entries = [crate::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
        entries[0] = crate::resolver::select("1.1.1.1#dns.google").expect("dot ns");
        entries[1] = crate::resolver::select("8.8.8.8#dns.example").expect("dot ns");
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
        Some(ActiveResolver::at(1, 2)),
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
            Some(ActiveResolver::at(1, 2)),
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
        Some(ActiveResolver::at(1, 2)),
        "one success leaves the probe armed"
    );
    assert_eq!(transport.failback_successes, 1);
    // Two successes are still not enough.
    transport
        .on_exchange_succeeded()
        .expect("success settles without a transport error");
    assert_eq!(
        transport.failback_source,
        Some(ActiveResolver::at(1, 2)),
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
        let mut entries = [crate::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
        entries[0] = crate::resolver::select("1.1.1.1#dns.google").expect("dot ns");
        entries[1] = crate::resolver::select("8.8.8.8").expect("plain ns");
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
        let mut entries = [crate::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
        entries[0] = crate::resolver::select("1.1.1.1").expect("plain ns");
        entries[1] = crate::resolver::select("8.8.8.8#dns.google").expect("dot ns");
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
        Some(ActiveResolver::at(1, 2)),
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
        transport.next_healthy_after_active(ActiveResolver::at(2, 3)),
        Some(ActiveResolver::at(1, 3)),
        "the scan wraps past the degraded primary back to the first healthy backup"
    );

    let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    let mut transport = seeded_transport(set);
    transport.degradations[2] = ResolverDegradation::Degraded;
    assert_eq!(
        transport.next_healthy_after_active(ActiveResolver::at(2, 3)),
        Some(ActiveResolver::at(0, 3)),
        "a wrap around the set edge prefers a healthy primary"
    );

    let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    let mut transport = seeded_transport(set);
    transport.degradations = [ResolverDegradation::Degraded; MAX_RESOLVERS];
    assert_eq!(
        transport.next_healthy_after_active(ActiveResolver::at(1, 3)),
        None,
        "every candidate degraded yields no relocation"
    );

    let set = resolver_set_of(&["1.1.1.1"]);
    let transport = seeded_transport(set);
    assert_eq!(
        transport.next_healthy_after_active(ActiveResolver::primary(1)),
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
        let silent = spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
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
        ActiveResolver::at(0, 3),
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
    transport.active_resolver = ActiveResolver::at(1, 3);
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
        Some(ActiveResolver::at(2, 3)),
        "the probe targets the only unexercised resolver"
    );
    let mut schedules = Schedules::new(2).unwrap();
    transport
        .note_failure(0, Family::A, true, &mut schedules, FailureReason::Connect)
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
    transport.failback_source = Some(ActiveResolver::at(1, 2));
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
        Some(ActiveResolver::at(1, 3)),
        "the first unprobed resolver is index 1"
    );
    assert_eq!(
        sweep.remaining,
        [false, false, true, false, false],
        "the started resolver leaves the remaining set"
    );
    assert_eq!(
        transport.active_resolver,
        ActiveResolver::at(1, 3),
        "the transport relocates onto the probe target"
    );
    assert_eq!(transport.peer().ip().to_string(), "8.8.8.8");
    assert!(
        transport.has_active_exchange(),
        "the probe exchange is in flight"
    );
}

#[test]
fn sweep_next_probe_returns_done_when_every_resolver_is_probed() {
    let set = resolver_set_of(&["1.1.1.1", "8.8.8.8"]);
    let mut transport = seeded_transport(set);
    transport.probe_sweep = Some(ProbeSweep {
        remaining: [false, false, false, false, false],
        active_before: ActiveResolver::at(0, 2),
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
        Some(ActiveResolver::at(1, 3)),
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
        active_before: ActiveResolver::at(0, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(2, 3)),
    });
    transport.active_resolver = ActiveResolver::at(2, 3);
    transport.repoint_to_active();
    transport.on_exchange_failed(now);
    assert_eq!(
        transport.active_resolver,
        ActiveResolver::at(0, 3),
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
        Some(ActiveResolver::at(2, 3)),
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
        active_before: ActiveResolver::at(0, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(2, 3)),
    });
    transport.active_resolver = ActiveResolver::at(2, 3);
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
        ActiveResolver::at(0, 3),
        "the probe failure still restores the pre-sweep active resolver"
    );
}

#[test]
fn successful_probe_records_ok_resets_probed_and_restores_active() {
    let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    let mut transport = seeded_transport(set);
    transport.probe_sweep = Some(ProbeSweep {
        remaining: [false, false, true, false, false],
        active_before: ActiveResolver::at(0, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(2, 3)),
    });
    transport.active_resolver = ActiveResolver::at(2, 3);
    transport.repoint_to_active();
    transport
        .on_exchange_succeeded()
        .expect("success settles without a transport error");
    assert_eq!(
        transport.active_resolver,
        ActiveResolver::at(0, 3),
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
        active_before: ActiveResolver::at(0, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(2, 3)),
    });
    transport.active_resolver = ActiveResolver::at(2, 3);
    transport.repoint_to_active();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe peer");
    let client = mio::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
    transport.conn = Some(DnsConn::Plain(client));
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
        ActiveResolver::at(0, 3),
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
        active_before: ActiveResolver::at(0, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: None,
    });

    // Phase 1: a normal active exchange publishes name-authorization state.
    let deadline = Instant::now() + Duration::from_millis(200);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)
        .unwrap();
    assert!(
        matches!(
            run_exchange_to_terminal(&mut transport, fqdn, &mut cache, &mut schedules, deadline),
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
        ActiveResolver::at(0, 3),
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
fn note_failure_records_failed_verdict_with_reason_and_clears_current() {
    let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    let mut transport = seeded_transport(set);
    transport.probe_sweep = Some(ProbeSweep {
        remaining: [false, false, true, false, false],
        active_before: ActiveResolver::at(0, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(2, 3)),
    });
    transport.active_resolver = ActiveResolver::at(2, 3);
    transport.repoint_to_active();
    let mut schedules = Schedules::new(2).unwrap();
    transport
        .note_failure(0, Family::A, true, &mut schedules, FailureReason::Connect)
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
        ActiveResolver::at(0, 3),
        "note_failure flows through the probe-mode restore"
    );
}

#[test]
fn sweep_probe_to_non_primary_is_never_hijacked_into_a_failback_probe() {
    let set = resolver_set_of(&["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    let mut transport = seeded_transport(set);
    let now = 1_000_000u64;
    // A window failover to the backup arms the failback grace with no source.
    transport.active_resolver = ActiveResolver::at(1, 3);
    transport.repoint_to_active();
    transport.failback_due = Some(now + FAILBACK_AFTER_SECS);
    transport.failback_source = None;
    // The sweep begins and probes the non-primary index 2.
    transport.probe_sweep = Some(ProbeSweep {
        remaining: [false, true, true, false, false],
        active_before: ActiveResolver::at(1, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(2, 3)),
    });
    transport.active_resolver = ActiveResolver::at(2, 3);
    transport.repoint_to_active();
    let fqdn = crate::config::Fqdn::parse("example.com:443").expect("fqdn");
    let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
    transport
        .start_exchange(&fqdn, Family::A, 0, deadline, Generation::INITIAL)
        .expect("probe exchange begins");
    assert_eq!(
        transport.active_resolver,
        ActiveResolver::at(2, 3),
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
        active_before: ActiveResolver::at(0, 3),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(2, 3)),
    });
    transport.active_resolver = ActiveResolver::at(2, 3);
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
        let mut entries = [crate::resolver::select("1.1.1.1").expect("ns"); MAX_RESOLVERS];
        entries[0] = crate::resolver::select("1.1.1.1#dns.google").expect("dot ns");
        entries[1] = crate::resolver::select("8.8.8.8").expect("plain ns");
        ResolverSet::from_slice(&entries[..2]).expect("resolver count fits")
    };
    let mut transport = seeded_transport(dot_set);
    transport
        .relocate_for_probe(ActiveResolver::at(1, 2))
        .expect("relocation succeeds");
    assert_eq!(
        transport.active_resolver,
        ActiveResolver::at(1, 2),
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
        active_before: ActiveResolver::at(0, 2),
        verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
        current: Some(ActiveResolver::at(1, 2)),
    });
    transport.on_exchange_failed(1_000_000u64);
    assert_eq!(transport.active_resolver, ActiveResolver::at(0, 2));
    assert_eq!(
        transport.take_probe_relocations(),
        0,
        "restoring the pre-sweep resolver counts no additional probe relocation"
    );
}
