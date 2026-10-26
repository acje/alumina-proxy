//! Dependency-free machine-instruction-count microbenchmark for the two
//! reachable parsing seams of the serving path: `ChInspector::feed` and
//! `ja4_fingerprint` (both in `alumina::client_hello`).
//!
//! This is a developer harness, not the serving binary. It links the
//! `alumina` library crate directly and drives the seams in a tight loop; it
//! does not exercise the socket, poll, or TLS layers of the serving binary
//! (`src/main.rs`). It is dependency-free: it uses only `std`, so instruction
//! counts are attributable to the seam under test, not to a benchmarking
//! framework.
//!
//! The `feed` seam is measured with a differential baseline. Loop A measures
//! `ChInspector::new()` construction alone; loop B measures construction plus
//! a single `feed` that must return `Inspect::Complete`; the reported
//! `feed_parse_delta_ns` is loop B minus loop A. The `ja4_fingerprint` seam is
//! measured directly on the wire-order lists extracted from one parsed
//! `ClientHello` fixture.
//!
//! The embedded fixture is a TLS 1.3-only `ClientHello` (record and legacy
//! version `0x0303`, `supported_versions` offering only `0x0304`), built at
//! startup into a `Vec<u8>`.
//!
//! # Measuring
//!
//! On Linux, count retired instructions with `perf`:
//!
//! ```text
//! perf stat -e instructions -r 5 -- target/release/parser_bench [N]
//! ```
//!
//! On macOS there is no `perf`; the harness reports wall-clock nanoseconds
//! only, as a smoke signal, never as a substitute for instruction counts.
//!
//! The first positional argument is the iteration count `N`; the default is
//! chosen so the timed region runs for roughly one second on a modern core.
//! Output is machine-parseable `key=value` lines plus the computed `ja4`
//! fingerprint and a checksum that folds every per-iteration fingerprint into
//! a single 36-byte wrapping-addition accumulator so the compiler cannot elide
//! the loop.

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use alumina::client_hello::{ChInspector, Inspect, ja4_fingerprint};

const RECORD_CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const RANDOM_LEN: usize = 32;
const TLS12_WIRE: u16 = 0x0303;
const TLS13_WIRE: u16 = 0x0304;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const DEFAULT_ITERATIONS: u64 = 500_000;

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_extension(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    push_u16(out, ty);
    push_u16(
        out,
        u16::try_from(data.len()).expect("extension data fits u16"),
    );
    out.extend_from_slice(data);
}

fn supported_versions_data() -> Vec<u8> {
    let mut data = Vec::new();
    push_u8(&mut data, 2);
    push_u16(&mut data, TLS13_WIRE);
    data
}

fn server_name_data(name: &[u8]) -> Vec<u8> {
    let mut names = Vec::new();
    push_u8(&mut names, 0);
    push_u16(
        &mut names,
        u16::try_from(name.len()).expect("sni name fits u16"),
    );
    names.extend_from_slice(name);
    let mut data = Vec::new();
    push_u16(
        &mut data,
        u16::try_from(names.len()).expect("sni names block fits u16"),
    );
    data.extend_from_slice(&names);
    data
}

fn alpn_data(protos: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for proto in protos {
        push_u8(
            &mut list,
            u8::try_from(proto.len()).expect("alpn proto fits u8"),
        );
        list.extend_from_slice(proto);
    }
    let mut data = Vec::new();
    push_u16(
        &mut data,
        u16::try_from(list.len()).expect("alpn list fits u16"),
    );
    data.extend_from_slice(&list);
    data
}

fn sigalgs_data(algs: &[u16]) -> Vec<u8> {
    let mut data = Vec::new();
    push_u16(
        &mut data,
        u16::try_from(algs.len() * 2).expect("sigalgs list fits u16"),
    );
    for alg in algs {
        push_u16(&mut data, *alg);
    }
    data
}

fn build_tls13_hello() -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, TLS12_WIRE);
    body.extend_from_slice(&[0xAB; RANDOM_LEN]);
    push_u8(&mut body, 0);
    push_u16(&mut body, 8);
    for cipher in [0x1301u16, 0x1302, 0x1303, 0x1304] {
        push_u16(&mut body, cipher);
    }
    push_u8(&mut body, 1);
    push_u8(&mut body, 0);
    let mut exts = Vec::new();
    push_extension(
        &mut exts,
        EXT_SUPPORTED_VERSIONS,
        &supported_versions_data(),
    );
    push_extension(
        &mut exts,
        EXT_SERVER_NAME,
        &server_name_data(b"bench.example"),
    );
    push_extension(
        &mut exts,
        EXT_ALPN,
        &alpn_data(&[b"h2".as_slice(), b"http/1.1".as_slice()]),
    );
    push_extension(
        &mut exts,
        EXT_SIGNATURE_ALGORITHMS,
        &sigalgs_data(&[0x0403, 0x0804, 0x0401]),
    );
    push_u16(
        &mut body,
        u16::try_from(exts.len()).expect("extensions blob fits u16"),
    );
    body.extend_from_slice(&exts);

    let mut handshake = Vec::new();
    push_u8(&mut handshake, HANDSHAKE_CLIENT_HELLO);
    let body_len = u32::try_from(body.len()).expect("client hello body fits u24");
    handshake.extend_from_slice(&body_len.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    push_u8(&mut record, RECORD_CONTENT_HANDSHAKE);
    push_u16(&mut record, TLS12_WIRE);
    push_u16(
        &mut record,
        u16::try_from(handshake.len()).expect("handshake fits u16"),
    );
    record.extend_from_slice(&handshake);
    record
}

fn bench_feed(hello: &[u8], iterations: u64) -> (u128, u128) {
    let construct_start = Instant::now();
    for _ in 0..iterations {
        let mut inspector = ChInspector::new();
        black_box(&mut inspector);
    }
    let construct_ns = construct_start.elapsed().as_nanos();

    let parse_start = Instant::now();
    for _ in 0..iterations {
        let mut inspector = ChInspector::new();
        let result = inspector.feed(hello);
        black_box(&result);
        assert!(
            matches!(result, Ok(Inspect::Complete { .. })),
            "fixture must complete in a single feed"
        );
        black_box(&mut inspector);
    }
    let construct_plus_parse_ns = parse_start.elapsed().as_nanos();

    (construct_ns, construct_plus_parse_ns)
}

fn bench_ja4(hello: &[u8], iterations: u64) -> (u128, [u8; 36], [u8; 36]) {
    let mut inspector = ChInspector::new();
    let result = inspector.feed(hello);
    assert!(
        matches!(result, Ok(Inspect::Complete { .. })),
        "fixture must complete in a single feed"
    );
    let ch = inspector.hello().expect("complete hello is present");
    let version = ch.offered_versions().first().copied().unwrap_or(TLS13_WIRE);
    let ciphers = ch.ciphers();
    let extensions = ch.extensions();
    let alpn = ch.alpn_first_value();
    let sigalgs = ch.sigalgs();
    let fingerprint = ja4_fingerprint(version, ciphers, extensions, alpn, sigalgs);

    let mut acc = [0u8; 36];
    let start = Instant::now();
    for _ in 0..iterations {
        let fp = ja4_fingerprint(
            black_box(version),
            black_box(ciphers),
            black_box(extensions),
            black_box(alpn),
            black_box(sigalgs),
        );
        for (slot, byte) in acc.iter_mut().zip(fp) {
            *slot = slot.wrapping_add(byte);
        }
        black_box(&acc);
    }
    let elapsed = start.elapsed().as_nanos();

    (elapsed, fingerprint, acc)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn parse_iterations() -> u64 {
    let mut args = std::env::args().skip(1);
    let Some(arg) = args.next() else {
        return DEFAULT_ITERATIONS;
    };
    let parsed = arg
        .parse::<u64>()
        .expect("iteration count must be a non-negative integer");
    assert!(parsed != 0, "iteration count must be at least 1");
    parsed
}

fn main() {
    let iterations = parse_iterations();
    let hello = build_tls13_hello();
    let (construct_ns, construct_plus_parse_ns) = bench_feed(&hello, iterations);
    let parse_delta_ns = construct_plus_parse_ns.saturating_sub(construct_ns);
    let (ja4_ns, fingerprint, checksum) = bench_ja4(&hello, iterations);
    let fingerprint_hex = hex(&fingerprint);
    let checksum_hex = hex(&checksum);

    println!("iterations={iterations}");
    println!("feed_construct_ns={construct_ns}");
    println!("feed_construct_plus_parse_ns={construct_plus_parse_ns}");
    println!("feed_parse_delta_ns={parse_delta_ns}");
    println!("feed_parse_isolation=differential_baseline");
    println!("ja4_ns={ja4_ns}");
    println!("ja4_fingerprint={fingerprint_hex}");
    println!("ja4_checksum={checksum_hex}");
}
