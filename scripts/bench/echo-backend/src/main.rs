use std::env;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const PEEK_CAP: usize = 4096;
const ECHO_CAP: usize = 65536;
const MAX_CONNECTIONS: usize = 1024;
const CONNECT_MARKER: &[u8] = b"CONNECT ";
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
const ESTABLISHED_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const DEFAULT_ADDR: &str = "8.8.8.8:443";

#[derive(Clone, Copy)]
enum Preamble {
    None,
    Established,
    Abandoned,
}

struct Args {
    cert: String,
    key: String,
    addr: String,
}

fn print_usage() {
    eprintln!("usage: echo-backend --cert <pem> --key <pem> [--addr {DEFAULT_ADDR}]");
}

fn parse_args() -> Args {
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut addr = String::from(DEFAULT_ADDR);
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--cert" => cert = it.next(),
            "--key" => key = it.next(),
            "--addr" => addr = it.next().unwrap_or_else(|| String::from(DEFAULT_ADDR)),
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => {
                eprintln!("unknown argument: {arg}");
                print_usage();
                process::exit(2);
            }
        }
    }
    let cert = cert.unwrap_or_else(|| {
        eprintln!("missing --cert");
        process::exit(2);
    });
    let key = key.unwrap_or_else(|| {
        eprintln!("missing --key");
        process::exit(2);
    });
    Args { cert, key, addr }
}

fn rustls_as_io(err: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut reader = BufReader::new(bytes.as_slice());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    Ok(certs?)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut reader = BufReader::new(bytes.as_slice());
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "no private key found in file").into()
    })
}

fn server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(rustls_as_io)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(rustls_as_io)?;
    Ok(Arc::new(config))
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_TERMINATOR.len())
        .position(|window| window == HEADER_TERMINATOR)
}

fn read_exact_padded(stream: &mut TcpStream, total: usize) -> io::Result<()> {
    let mut left = total;
    let mut buf = [0u8; PEEK_CAP];
    while left > 0 {
        let want = left.min(buf.len());
        let n = stream.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-CONNECT-header",
            ));
        }
        left -= n;
    }
    Ok(())
}

fn consume_connect_preamble(stream: &mut TcpStream) -> io::Result<Preamble> {
    let mut buf = [0u8; PEEK_CAP];
    let n = stream.peek(&mut buf)?;
    if n == 0 {
        return Ok(Preamble::Abandoned);
    }
    if !buf[..n].starts_with(CONNECT_MARKER) {
        return Ok(Preamble::None);
    }
    let mut prev = n;
    loop {
        if let Some(pos) = find_terminator(&buf[..prev]) {
            read_exact_padded(stream, pos + HEADER_TERMINATOR.len())?;
            stream.write_all(ESTABLISHED_RESPONSE)?;
            return Ok(Preamble::Established);
        }
        let m = stream.peek(&mut buf)?;
        if m == 0 || m == prev {
            return Ok(Preamble::Abandoned);
        }
        prev = m;
    }
}

fn handle_connection(mut stream: TcpStream, config: Arc<ServerConfig>) -> io::Result<()> {
    match consume_connect_preamble(&mut stream)? {
        Preamble::Abandoned => return Ok(()),
        Preamble::None | Preamble::Established => {}
    }
    let conn = ServerConnection::new(config).map_err(rustls_as_io)?;
    let mut tls = StreamOwned::new(conn, stream);
    let mut buf = [0u8; ECHO_CAP];
    loop {
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        tls.write_all(&buf[..n])?;
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let config = server_config(&args.cert, &args.key)?;
    let listener = TcpListener::bind(&args.addr)?;
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _peer) = listener.accept()?;
        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            drop(stream);
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let active_for_closure = Arc::clone(&active);
        let config = Arc::clone(&config);
        let spawn = std::thread::Builder::new()
            .name(String::from("echo-backend-connection"))
            .spawn(move || {
                let _lease = ActiveGuard(active_for_closure);
                let _ = handle_connection(stream, config);
            });
        if spawn.is_err() {
            active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
