//! Test-only owner of the loopback plain-DNS responder shared by the gate
//! binaries and the storage startup-window tests: the two-byte length framing
//! readers and writers, the responder thread that answers every query through
//! one caller-supplied builder, the parsed-query reply skeleton, the
//! answer-record writer, and the positive A/AAAA answer builder.
//!
//! Both owners drive a real TCP DNS exchange against a runtime that dials a
//! bare-IP resolver, so the framing and the reply shape live in exactly one
//! place. The builder is a closure because the startup-window tests also answer
//! with CNAME shapes; the gate binaries answer positively for every query.
#![allow(
    dead_code,
    reason = "shared `#[path]` owner; each inclusion site uses only its subset"
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

/// A local loopback plain-DNS responder that answers every query through
/// `on_query`, so a runtime with a bare-IP resolver reaches its startup window
/// without external network.
pub(super) struct DnsResponder {
    pub(super) addr: SocketAddr,
}

impl DnsResponder {
    /// Binds an ephemeral loopback port and answers queries on a detached
    /// thread until the listener or a connection ends the exchange.
    pub(super) fn spawn<F>(mut on_query: F) -> DnsResponder
    where
        F: FnMut(Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder address");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else {
                    break;
                };
                while let Some(query) = read_query(&mut sock) {
                    let Some(reply) = on_query(query) else {
                        break;
                    };
                    if write_message(&mut sock, &reply).is_err() {
                        break;
                    }
                }
            }
        });
        DnsResponder { addr }
    }
}

/// TCP-framed DNS over TCP: reads one 2-byte length-prefixed query.
fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut lenb = [0u8; 2];
    if sock.read_exact(&mut lenb).is_err() {
        return None;
    }
    let qlen = usize::from(u16::from_be_bytes(lenb));
    if qlen == 0 || qlen > 2048 {
        return None;
    }
    let mut q = vec![0u8; qlen];
    if sock.read_exact(&mut q).is_err() {
        return None;
    }
    Some(q)
}

/// Writes one 2-byte length-prefixed DNS over TCP message.
fn write_message(sock: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(
        &u16::try_from(msg.len())
            .expect("dns message fits u16 length prefix")
            .to_be_bytes(),
    );
    out.extend_from_slice(msg);
    sock.write_all(&out)?;
    sock.flush()
}

/// One parsed single-question query: the transaction id, and the question's
/// owner name, type, and raw wire bytes.
pub(super) struct Query<'a> {
    tid: u16,
    pub(super) question: &'a [u8],
    pub(super) qname: &'a [u8],
    pub(super) qtype: u16,
}

impl<'a> Query<'a> {
    /// Parses a query that is at least a fixed header plus one type/class pair
    /// wide; the question section is everything after the twelve-byte header.
    pub(super) fn parse(query: &'a [u8]) -> Option<Query<'a>> {
        if query.len() < 16 {
            return None;
        }
        Some(Query {
            tid: u16::from_be_bytes([query[0], query[1]]),
            question: &query[12..],
            qname: &query[12..query.len() - 4],
            qtype: u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]),
        })
    }

    /// Starts a reply with the query's transaction id, one question echoed
    /// verbatim, `answers` declared answer records, and no authority or
    /// additional records. `capacity` is the caller's allocation hint; the
    /// caller's answer records may extend past it.
    pub(super) fn reply(&self, capacity: usize, answers: u16) -> Vec<u8> {
        let mut msg = Vec::with_capacity(capacity);
        msg.extend_from_slice(&self.tid.to_be_bytes());
        msg.extend_from_slice(&0x8000u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&answers.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(self.question);
        msg
    }
}

const RDATA_A: [u8; 4] = [1, 1, 1, 1];
const RDATA_AAAA: [u8; 16] = [
    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
];

/// The terminal record data for a query type the responder answers, or `None`
/// for every other type.
pub(super) const fn positive_rdata(qtype: u16) -> Option<&'static [u8]> {
    match qtype {
        1 => Some(&RDATA_A),
        28 => Some(&RDATA_AAAA),
        _ => None,
    }
}

/// Appends one answer record: owner, type, class 1, TTL, and the
/// length-prefixed record data. Every answer builder shares this layout, so the
/// field order and the class live here.
pub(super) fn push_answer(msg: &mut Vec<u8>, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) {
    msg.extend_from_slice(owner);
    msg.extend_from_slice(&rtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&ttl.to_be_bytes());
    msg.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("answer rdata fits u16 wire length")
            .to_be_bytes(),
    );
    msg.extend_from_slice(rdata);
}

/// Builds a positive DNS reply (A or AAAA) echoing the question.
pub(super) fn build_positive(query: &[u8]) -> Option<Vec<u8>> {
    let q = Query::parse(query)?;
    let rdata = positive_rdata(q.qtype)?;
    let mut msg = q.reply(query.len() + 22, 1);
    push_answer(&mut msg, q.qname, q.qtype, 300, rdata);
    Some(msg)
}
