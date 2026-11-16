//! Hermetic loopback DNS-over-TLS transport tests (§Protocol contract;
//! §Configuration & DNS): a rustls `ServerConnection` answers the transport's
//! `DoT` exchanges so the strict-SPKI-pin, FQDN/SAN-identity, and CA-chain
//! verifier branches are exercised against deterministic certificates — no real `DoT`
//! resolver is ever dialed (docs contract, alumina-dot-chain-v1-v5).

use super::*;
use crate::config::parse_config_document;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// The loopback `DoT` identity: the FQDN the transport sends as SNI and
/// validates against the presented certificate's SAN.
const DOT_FQDN: &str = "dot.test";
/// Self-signed ECDSA P-256 certificate, CN=`dot.test`, SAN `DNS:dot.test`.
/// Its subject-public-key-info SHA-256 is [`PIN_B64`]; the matching pair
/// (`GOOD_KEY`) signs it.
pub(crate) const GOOD_CERT: &[u8] = &[
    0x30, 0x82, 0x01, 0x33, 0x30, 0x81, 0xda, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xd2,
    0xf8, 0xe4, 0xf2, 0x4c, 0x41, 0x09, 0xc5, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
    0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30,
    0x32, 0x30, 0x30, 0x38, 0x31, 0x33, 0x31, 0x35, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x30, 0x31,
    0x37, 0x30, 0x38, 0x31, 0x33, 0x31, 0x35, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x08, 0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30,
    0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x89, 0xae, 0xea, 0xf8, 0xb1, 0x29, 0x78, 0xde,
    0x09, 0x08, 0x34, 0x7f, 0x9d, 0x12, 0x90, 0x05, 0x10, 0x59, 0xe7, 0xc0, 0x2b, 0xcb, 0x64, 0x2c,
    0x88, 0x70, 0x4e, 0x88, 0x05, 0xbd, 0x8d, 0x6d, 0xf2, 0x8e, 0xeb, 0x48, 0xa9, 0xf5, 0x47, 0xad,
    0x1b, 0x8a, 0xc4, 0xa1, 0x67, 0x33, 0xea, 0xa4, 0x0a, 0x46, 0xc1, 0x7f, 0x06, 0xc0, 0x00, 0x0d,
    0x4c, 0x5d, 0xdd, 0x69, 0x54, 0x09, 0xd1, 0x61, 0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x03,
    0x55, 0x1d, 0x11, 0x04, 0x0c, 0x30, 0x0a, 0x82, 0x08, 0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73,
    0x74, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00,
    0x30, 0x45, 0x02, 0x21, 0x00, 0xd9, 0x7d, 0xb4, 0x8f, 0xed, 0xbc, 0x84, 0x88, 0x07, 0x86, 0x44,
    0xeb, 0xf9, 0x61, 0x6f, 0x3a, 0x42, 0x84, 0x34, 0x41, 0xb1, 0x1a, 0xa5, 0xc7, 0xb2, 0x4d, 0xa2,
    0x56, 0x7e, 0x5f, 0x0b, 0xa6, 0x02, 0x20, 0x78, 0xb5, 0x4e, 0x87, 0xd1, 0x14, 0xcb, 0xa9, 0xe2,
    0x71, 0xe9, 0xe4, 0x9a, 0xc1, 0x81, 0xc3, 0xc8, 0x88, 0x8e, 0xb3, 0x6e, 0x78, 0xed, 0xc1, 0x48,
    0xca, 0xb1, 0xe5, 0xb0, 0x84, 0xd3, 0xda,
];

/// The same key and SPKI as [`GOOD_CERT`] (so [`PIN_B64`] matches) but already
/// expired: notBefore 2020-01-01, notAfter 2021-01-01. The pinned verifier
/// checks only SAN plus SPKI pin, never certificate validity, so this
/// certificate must still be accepted.
const EXPIRED_CERT: &[u8] = &[
    0x30, 0x82, 0x01, 0x4a, 0x30, 0x81, 0xf1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x10, 0x00,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x13, 0x31, 0x11,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73,
    0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5a, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x64, 0x6f,
    0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0x89, 0xae, 0xea, 0xf8, 0xb1, 0x29, 0x78, 0xde, 0x09, 0x08, 0x34, 0x7f, 0x9d, 0x12, 0x90,
    0x05, 0x10, 0x59, 0xe7, 0xc0, 0x2b, 0xcb, 0x64, 0x2c, 0x88, 0x70, 0x4e, 0x88, 0x05, 0xbd, 0x8d,
    0x6d, 0xf2, 0x8e, 0xeb, 0x48, 0xa9, 0xf5, 0x47, 0xad, 0x1b, 0x8a, 0xc4, 0xa1, 0x67, 0x33, 0xea,
    0xa4, 0x0a, 0x46, 0xc1, 0x7f, 0x06, 0xc0, 0x00, 0x0d, 0x4c, 0x5d, 0xdd, 0x69, 0x54, 0x09, 0xd1,
    0x61, 0xa3, 0x35, 0x30, 0x33, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
    0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
    0x02, 0x05, 0xa0, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0c, 0x30, 0x0a, 0x82, 0x08,
    0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xf1, 0x1d, 0xf1, 0x43,
    0x1f, 0x57, 0xd8, 0x4e, 0xe6, 0xca, 0x93, 0xa7, 0x59, 0x6a, 0xa1, 0x7a, 0x31, 0xc5, 0xba, 0x6d,
    0x2f, 0xa3, 0xd6, 0x0a, 0x59, 0x5c, 0x46, 0xec, 0x13, 0xf8, 0x1b, 0x39, 0x02, 0x20, 0x33, 0xeb,
    0x43, 0xc8, 0xcf, 0x17, 0xa5, 0x4b, 0x7c, 0xc8, 0x28, 0xfb, 0x1f, 0x8d, 0xfe, 0x1a, 0xb9, 0xfa,
    0x2d, 0xa4, 0x65, 0x31, 0xaa, 0xa0, 0xcf, 0xe3, 0x52, 0xdf, 0x37, 0x63, 0xb6, 0xd4,
];

/// The same key and SPKI as [`GOOD_CERT`] (so [`PIN_B64`] matches) but not yet
/// valid: notBefore 2030-01-01, notAfter 2040-01-01. The pinned verifier
/// checks only SAN plus SPKI pin, never certificate validity, so this
/// certificate must still be accepted.
const NOT_YET_VALID_CERT: &[u8] = &[
    0x30, 0x82, 0x01, 0x49, 0x30, 0x81, 0xf1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x10, 0x01,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x13, 0x31, 0x11,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73,
    0x74, 0x30, 0x1e, 0x17, 0x0d, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5a, 0x17, 0x0d, 0x34, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x64, 0x6f,
    0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0x89, 0xae, 0xea, 0xf8, 0xb1, 0x29, 0x78, 0xde, 0x09, 0x08, 0x34, 0x7f, 0x9d, 0x12, 0x90,
    0x05, 0x10, 0x59, 0xe7, 0xc0, 0x2b, 0xcb, 0x64, 0x2c, 0x88, 0x70, 0x4e, 0x88, 0x05, 0xbd, 0x8d,
    0x6d, 0xf2, 0x8e, 0xeb, 0x48, 0xa9, 0xf5, 0x47, 0xad, 0x1b, 0x8a, 0xc4, 0xa1, 0x67, 0x33, 0xea,
    0xa4, 0x0a, 0x46, 0xc1, 0x7f, 0x06, 0xc0, 0x00, 0x0d, 0x4c, 0x5d, 0xdd, 0x69, 0x54, 0x09, 0xd1,
    0x61, 0xa3, 0x35, 0x30, 0x33, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
    0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
    0x02, 0x05, 0xa0, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0c, 0x30, 0x0a, 0x82, 0x08,
    0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x61, 0x08, 0x18, 0xba, 0xe9,
    0xa1, 0x21, 0x83, 0xbb, 0xae, 0x5a, 0x29, 0x85, 0xf6, 0x20, 0xe2, 0xc6, 0x9d, 0x10, 0xbd, 0xde,
    0x38, 0x4a, 0xa5, 0xfd, 0x30, 0x8e, 0x40, 0x0c, 0x27, 0xfb, 0xae, 0x02, 0x20, 0x3c, 0x1e, 0x16,
    0x68, 0x72, 0xe0, 0xf0, 0x4b, 0x2a, 0x96, 0x58, 0x40, 0xf5, 0xd0, 0x1f, 0xc1, 0xaf, 0xa9, 0x81,
    0xfa, 0xa2, 0x27, 0x9c, 0xb7, 0xad, 0x22, 0x1b, 0xe1, 0x47, 0x2c, 0x5e, 0xcd,
];

/// The PKCS#8 DER private key behind [`GOOD_CERT`] and [`SAN_MISMATCH_CERT`]
/// (same key, same SPKI, same pin, different SAN).
pub(crate) const GOOD_KEY: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0xfd, 0xa6, 0x3f, 0x2a, 0xe9, 0xa3, 0x40, 0x66, 0x2c, 0x09, 0xe8, 0x04,
    0x36, 0x02, 0x4e, 0x26, 0x06, 0x39, 0x52, 0x29, 0x88, 0xe6, 0x3a, 0xe7, 0x5e, 0x7b, 0xc2, 0x3b,
    0xf2, 0x97, 0x25, 0xee, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x89, 0xae, 0xea, 0xf8, 0xb1, 0x29,
    0x78, 0xde, 0x09, 0x08, 0x34, 0x7f, 0x9d, 0x12, 0x90, 0x05, 0x10, 0x59, 0xe7, 0xc0, 0x2b, 0xcb,
    0x64, 0x2c, 0x88, 0x70, 0x4e, 0x88, 0x05, 0xbd, 0x8d, 0x6d, 0xf2, 0x8e, 0xeb, 0x48, 0xa9, 0xf5,
    0x47, 0xad, 0x1b, 0x8a, 0xc4, 0xa1, 0x67, 0x33, 0xea, 0xa4, 0x0a, 0x46, 0xc1, 0x7f, 0x06, 0xc0,
    0x00, 0x0d, 0x4c, 0x5d, 0xdd, 0x69, 0x54, 0x09, 0xd1, 0x61,
];

/// Same key and SPKI as [`GOOD_CERT`] but SAN `DNS:alt.test`: pin matches
/// [`PIN_B64`] while the FQDN/SAN check must reject it.
const SAN_MISMATCH_CERT: &[u8] = &[
    0x30, 0x82, 0x01, 0x34, 0x30, 0x81, 0xda, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xa2,
    0x84, 0x3a, 0x37, 0xd2, 0xca, 0x6e, 0xd2, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
    0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30,
    0x32, 0x30, 0x30, 0x38, 0x31, 0x33, 0x31, 0x35, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x30, 0x31,
    0x37, 0x30, 0x38, 0x31, 0x33, 0x31, 0x35, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x08, 0x64, 0x6f, 0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30,
    0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x89, 0xae, 0xea, 0xf8, 0xb1, 0x29, 0x78, 0xde,
    0x09, 0x08, 0x34, 0x7f, 0x9d, 0x12, 0x90, 0x05, 0x10, 0x59, 0xe7, 0xc0, 0x2b, 0xcb, 0x64, 0x2c,
    0x88, 0x70, 0x4e, 0x88, 0x05, 0xbd, 0x8d, 0x6d, 0xf2, 0x8e, 0xeb, 0x48, 0xa9, 0xf5, 0x47, 0xad,
    0x1b, 0x8a, 0xc4, 0xa1, 0x67, 0x33, 0xea, 0xa4, 0x0a, 0x46, 0xc1, 0x7f, 0x06, 0xc0, 0x00, 0x0d,
    0x4c, 0x5d, 0xdd, 0x69, 0x54, 0x09, 0xd1, 0x61, 0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x03,
    0x55, 0x1d, 0x11, 0x04, 0x0c, 0x30, 0x0a, 0x82, 0x08, 0x61, 0x6c, 0x74, 0x2e, 0x74, 0x65, 0x73,
    0x74, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00,
    0x30, 0x46, 0x02, 0x21, 0x00, 0xff, 0x61, 0x35, 0xf9, 0x58, 0x32, 0xc5, 0xfe, 0x94, 0xf0, 0xa2,
    0x8b, 0xe5, 0x23, 0xc2, 0x91, 0xe8, 0xe4, 0x56, 0x01, 0x1c, 0x6b, 0x88, 0x26, 0x86, 0x9a, 0x47,
    0xa3, 0x16, 0x70, 0xc1, 0x53, 0x02, 0x21, 0x00, 0xfa, 0xb8, 0xaf, 0x97, 0xf7, 0x57, 0x46, 0xa9,
    0x55, 0x63, 0xf1, 0xd3, 0x0d, 0x85, 0x36, 0x1b, 0x4b, 0xe3, 0xfd, 0x45, 0xcb, 0xf1, 0xfe, 0xd4,
    0xd6, 0x20, 0xb3, 0x07, 0xe9, 0x97, 0xab, 0xbd,
];

/// Unpadded base64 SHA-256 of [`GOOD_CERT`]'s subject public key info: the
/// strict SPKI pin the transport's verifier compares on every pinned handshake.
const PIN_B64: &str = "Neh7ibmf4XjPYrBqu/hlbW4Ibp23X3uuja0AU85JHgY";

/// The pinned resolver line: `IP#fqdn#pin-sha256=<pin>` (port 853 by grammar).
/// Built from [`PIN_B64`] so the embedded pin and the test constant cannot
/// drift apart; `dot_config` needs a `&str`, so the helper owns one `String`.
pub(crate) fn pinned_resolver() -> String {
    format!("127.0.0.1#{DOT_FQDN}#pin-sha256={PIN_B64}")
}

/// The same identity with a valid-but-wrong pin: 32 zero bytes, 43 unpadded
/// base64 chars (the canonical zero vector), so the handshake must reject the
/// presented certificate on the pin comparison, not on parsing.
const WRONG_PINNED_RESOLVER: &str =
    "127.0.0.1#dot.test#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The same identity without a pin: the CA-chain branch against an empty root
/// store — a self-signed certificate must be deterministically rejected.
const UNPINNED_RESOLVER: &str = "127.0.0.1#dot.test";

fn ns(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)
}

/// A two-name allowlist configuration whose sole resolver is the given `DoT`
/// resolver line; the transport dials the injected loopback peer while the
/// TLS identity (FQDN plus optional pin) comes from this resolver set.
pub(crate) fn dot_config(resolver_line: &str) -> Config {
    let doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"{resolver_line}\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"beta.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
    );
    parse_config_document(&doc).expect("valid pinned-dot config")
}

/// A declared (`root_validating_no_stale`) counterpart of [`dot_config`]: the
/// same allowlist and pinned primary, but the saved set carries the declared
/// recursion policy so a completed real pinned exchange must qualify.
fn dot_config_declared(resolver_line: &str) -> Config {
    let doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"{resolver_line}\"]\nrecursive_dnssec_policy = \"root_validating_no_stale\"\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"beta.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
    );
    parse_config_document(&doc).expect("valid declared pinned-dot config")
}

struct DotExchange {
    transport: StartupDns,
    cache: Cache,
    schedules: Schedules,
}

impl DotExchange {
    fn new(cfg: &Config, port: u16) -> Self {
        let mut transport = StartupDns::new().expect("startup dns transport");
        transport.addr = ns(port);
        transport.now0 = 1_000_000;
        transport.resolvers = Some(*cfg.resolver_set());
        transport.active_resolver = ActiveResolver::primary_of(cfg.resolver_set());
        transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
            fqdn: *fqdn,
            pin: cfg.resolver_set().primary().pin().copied(),
        });
        Self {
            transport,
            cache: Cache::new(2).expect("two-name test cache"),
            schedules: Schedules::new(2).expect("two-name test schedules"),
        }
    }

    fn start_family_a(&mut self, fqdn: &Fqdn, ordinal: usize, deadline: Instant) {
        super::tests::start_startup_exchange(&mut self.transport, fqdn, ordinal, deadline);
    }

    fn drive(&mut self, fqdn: &Fqdn, deadline: Instant) -> Option<TurnResult> {
        self.drive_observed(fqdn, deadline, |_, _| {})
    }

    fn drive_shared(
        &mut self,
        fqdn: &Fqdn,
        deadline: Instant,
        poll: &mut Poll,
        events: &mut Events,
    ) -> TurnResult {
        drive_to_terminal(
            &mut self.transport,
            &mut self.cache,
            &mut self.schedules,
            fqdn,
            deadline,
            poll,
            events,
        )
    }

    fn drive_observed(
        &mut self,
        fqdn: &Fqdn,
        deadline: Instant,
        mut observe: impl FnMut(&StartupDns, ExchangeStep),
    ) -> Option<TurnResult> {
        for _ in 0..256 {
            if let Some(step) = self.transport.exchange_step() {
                observe(&self.transport, step);
            }
            match self
                .transport
                .advance_exchange(fqdn, &mut self.cache, &mut self.schedules)
                .expect("a live loopback DoT exchange advances without a fatal error")
            {
                TurnResult::Pending => {
                    if self
                        .transport
                        .exchange_deadline()
                        .is_some_and(|d| Instant::now() >= d)
                    {
                        continue;
                    }
                    let _ = self
                        .transport
                        .wait_dns_readiness(deadline)
                        .expect("the loopback peer answers within the exchange deadline");
                }
                terminal => return Some(terminal),
            }
        }
        None
    }
}

fn bindings_of(
    cache: &Cache,
    ordinal: usize,
    family: Family,
) -> Vec<crate::eligibility::NumericAddr> {
    let name = cache
        .name_index(ordinal)
        .expect("the test cache admits every allowlist ordinal");
    cache
        .entry(name, family)
        .expect("an admitted test name has an entry for every family")
        .bindings()
        .to_vec()
}

fn question_bytes(query: &[u8]) -> Vec<u8> {
    query[12..].to_vec()
}

/// Builds a positive DNS reply mirroring the query's transaction id, name, and
/// record type (A/AAAA), with a fixed TTL and in-allowlist owner so the
/// transport's validation publishes the answer.
fn echo_positive(query: &[u8]) -> Vec<u8> {
    let tid = u16::from_be_bytes([query[0], query[1]]);
    let qname = &query[12..query.len() - 4];
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let rdata: Vec<u8> = match qtype {
        1 => vec![93, 184, 216, 34],
        28 => vec![
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ],
        _ => Vec::new(),
    };
    let mut msg = super::tests::dns_header(tid, 0x8180, 1);
    msg.extend_from_slice(&question_bytes(query));
    msg.extend_from_slice(&super::tests::record(qname, qtype, 120, &rdata));
    msg
}

/// Builds a structurally valid positive reply whose transaction id differs
/// from the query's, so the transport's transaction-id check must reject it.
fn wrong_tid_reply(query: &[u8]) -> Vec<u8> {
    let tid = u16::from_be_bytes([query[0], query[1]]).wrapping_add(1);
    let mut reply = echo_positive(query);
    reply[0] = (tid >> 8) as u8;
    reply[1] = (tid & 0xff) as u8;
    reply
}

/// Builds a well-formed-length message that is not a response: it echoes the
/// query's transaction id but sets QR=0, so response parsing rejects it as
/// `NotResponse` instead of publishing anything.
fn mangled_reply(query: &[u8]) -> Vec<u8> {
    let tid = u16::from_be_bytes([query[0], query[1]]);
    let mut msg = super::tests::dns_header(tid, 0x0100, 0);
    msg.extend_from_slice(&question_bytes(query));
    msg
}

/// Builds the rustls server configuration presenting the embedded
/// certificate/key pair with the ring provider (no process-default provider is
/// installed by the transport).
fn server_config(cert: &'static [u8], key: &'static [u8]) -> ServerConfig {
    let provider = rustls::crypto::ring::default_provider();
    let certificate = CertificateDer::from(cert.to_vec());
    let key = PrivateKeyDer::try_from(key.to_vec()).expect("embedded ec p256 pkcs8 key");
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("loopback server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("loopback server certificate/key valid")
}

/// Builds a rustls server configuration restricted to TLS 1.3, so a client
/// offering only TLS 1.3 must negotiate 1.3 and still publish.
fn server_config_tls13(cert: &'static [u8], key: &'static [u8]) -> ServerConfig {
    let provider = rustls::crypto::ring::default_provider();
    let certificate = CertificateDer::from(cert.to_vec());
    let key = PrivateKeyDer::try_from(key.to_vec()).expect("embedded ec p256 pkcs8 key");
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("loopback server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("loopback server certificate/key valid")
}

/// Drains whatever decrypted plaintext the rustls connection currently buffers
/// into `plain`; never blocks on the socket. Returns whether any bytes were
/// drained, so the caller reads more TLS records only when the buffer is idle.
fn drain_plaintext(
    tls: &mut ServerConnection,
    plain: &mut Vec<u8>,
    scratch: &mut [u8],
) -> io::Result<bool> {
    let mut got = false;
    loop {
        match tls.reader().read(scratch) {
            Ok(0) => break,
            Ok(n) => {
                plain.extend_from_slice(&scratch[..n]);
                got = true;
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// Drains the rustls outbound record buffer to the blocking socket until no
/// further records are queued, tolerating transient WouldBlock/Interrupted.
fn flush_tls(tls: &mut ServerConnection, sock: &mut TcpStream) -> io::Result<()> {
    loop {
        match tls.write_tls(sock) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if !tls.wants_write() {
            break;
        }
    }
    Ok(())
}

/// Flushes one length-prefixed DNS message through the rustls writer and its
/// outbound TLS records to the blocking socket.
fn write_tls_message(
    tls: &mut ServerConnection,
    sock: &mut TcpStream,
    message: &[u8],
) -> io::Result<()> {
    tls.writer().write_all(
        &u16::try_from(message.len())
            .expect("reply fits u16")
            .to_be_bytes(),
    )?;
    tls.writer().write_all(message)?;
    tls.writer().flush()?;
    flush_tls(tls, sock)
}

/// Writes a length-prefixed DNS message so the length prefix and the body land
/// in separate TLS records: flush after the prefix, then flush after the body.
/// The transport's per-turn single-plaintext-chunk drain must accumulate both
/// records across turns before the full message is published.
fn write_tls_split(
    tls: &mut ServerConnection,
    sock: &mut TcpStream,
    message: &[u8],
) -> io::Result<()> {
    tls.writer().write_all(
        &u16::try_from(message.len())
            .expect("reply fits u16")
            .to_be_bytes(),
    )?;
    tls.writer().flush()?;
    flush_tls(tls, sock)?;
    tls.writer().write_all(message)?;
    tls.writer().flush()?;
    flush_tls(tls, sock)
}

/// The reply mode the loopback TLS responder applies to every query it
/// serves: a positive echo, or one of the adversarial responses the
/// transport must fail closed on (wrong transaction id, an over-limit
/// length prefix, or a malformed non-response).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AdversarialReply {
    /// Mirror the query with a valid positive answer (TID, name, type).
    Positive,
    /// A structurally valid reply whose transaction id differs from the query.
    WrongTid,
    /// A length prefix larger than `DNS_MSG_LIMIT`, so the transport's
    /// length guard fails closed before reading the body.
    Oversize,
    /// A well-formed-length message that is not a response (QR=0), so
    /// response parsing fails closed.
    Mangled,
    /// Serve exactly one positive reply then close the connection, so a
    /// retained transport's next exchange reads EOF and fails closed.
    ServeOnce,
    /// Split the reply across two TLS records: the length prefix flushed as
    /// its own record, then the body as a second record.
    SplitRecord,
}

/// Serves length-prefixed DNS queries over one accepted TLS connection until
/// the peer closes or the TLS layer errors. A failure (including a client
/// certificate-rejection alert on the handshake) simply ends the connection.
fn serve_queries(
    tls: &mut ServerConnection,
    sock: &mut TcpStream,
    mode: AdversarialReply,
) -> io::Result<()> {
    let mut plain: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        if let Some(query) = take_framed_query(&mut plain) {
            if serve_one_query(tls, sock, mode, &query)? {
                return Ok(());
            }
            continue;
        }
        if drain_plaintext(tls, &mut plain, &mut scratch)? {
            continue;
        }
        if !read_more_tls(tls, sock) {
            return Ok(());
        }
    }
}

fn take_framed_query(plain: &mut Vec<u8>) -> Option<Vec<u8>> {
    let prefix = plain.get(..2)?;
    let full = 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if plain.len() < full {
        return None;
    }
    let query = plain[2..full].to_vec();
    plain.drain(..full);
    Some(query)
}

fn serve_one_query(
    tls: &mut ServerConnection,
    sock: &mut TcpStream,
    mode: AdversarialReply,
    query: &[u8],
) -> io::Result<bool> {
    let reply = reply_for(mode, query);
    if mode == AdversarialReply::SplitRecord {
        write_tls_split(tls, sock, &reply)?;
    } else {
        write_tls_message(tls, sock, &reply)?;
    }
    Ok(mode == AdversarialReply::ServeOnce)
}

fn reply_for(mode: AdversarialReply, query: &[u8]) -> Vec<u8> {
    match mode {
        AdversarialReply::Positive
        | AdversarialReply::ServeOnce
        | AdversarialReply::SplitRecord => echo_positive(query),
        AdversarialReply::WrongTid => wrong_tid_reply(query),
        AdversarialReply::Oversize => vec![0u8; crate::dns::wire::DNS_MSG_LIMIT + 1],
        AdversarialReply::Mangled => mangled_reply(query),
    }
}

fn read_more_tls(tls: &mut ServerConnection, sock: &mut TcpStream) -> bool {
    match tls.read_tls(sock) {
        Ok(0) => return false,
        Ok(_) => {
            if tls.process_new_packets().is_err() {
                return false;
            }
        }
        Err(e)
            if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => {}
        Err(_) => return false,
    }
    true
}

/// Drives one accepted connection: completes the server handshake (returning
/// cleanly on a client alert or EOF) and then serves DNS queries.
fn serve_conn_blocking(
    sock: TcpStream,
    config: &Arc<ServerConfig>,
    mode: AdversarialReply,
    _observations: &ResponderObservations,
) {
    let mut sock = sock;
    let Ok(mut tls) = ServerConnection::new(Arc::clone(config)) else {
        return;
    };
    let completed = tls.complete_io(&mut sock);
    if completed.is_err() {
        return;
    }
    let _ = serve_queries(&mut tls, &mut sock, mode);
}

/// Drives one accepted connection: completes the server handshake, forces a
/// post-handshake traffic-key refresh (queuing a `KeyUpdate` record and flushing
/// any auto-queued session tickets), then serves DNS queries. The transport
/// must process the post-handshake records as non-application data and still
/// publish the DNS reply.
fn serve_conn_blocking_post_handshake(
    sock: TcpStream,
    config: &Arc<ServerConfig>,
    mode: AdversarialReply,
    _observations: &ResponderObservations,
) {
    let mut sock = sock;
    let Ok(mut tls) = ServerConnection::new(Arc::clone(config)) else {
        return;
    };
    if tls.complete_io(&mut sock).is_err() {
        return;
    }
    if tls.refresh_traffic_keys().is_err() {
        return;
    }
    if flush_tls(&mut tls, &mut sock).is_err() {
        return;
    }
    let _ = serve_queries(&mut tls, &mut sock, mode);
}

/// Drives one accepted connection like [`serve_conn_blocking`], and records
/// whether the client ended the TLS session with a `close_notify` alert. A
/// graceful close surfaces as a decrypted clean EOF (`Ok(0)` from the rustls
/// reader) after the alert record is processed; a bare TCP FIN surfaces as
/// `read_tls` returning `Ok(0)` with no alert, which leaves the observation
/// false.
fn serve_conn_blocking_observed(
    sock: TcpStream,
    config: &Arc<ServerConfig>,
    _mode: AdversarialReply,
    observations: &ResponderObservations,
) {
    let mut sock = sock;
    let Ok(mut tls) = ServerConnection::new(Arc::clone(config)) else {
        return;
    };
    if tls.complete_io(&mut sock).is_err() {
        return;
    }
    let mut plain: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        if let Some(query) = take_framed_query(&mut plain) {
            match serve_one_query(&mut tls, &mut sock, AdversarialReply::Positive, &query) {
                Ok(false) => continue,
                Ok(true) | Err(_) => return,
            }
        }
        match tls.reader().read(&mut scratch) {
            Ok(0) => {
                observations.close_notify.store(true, Ordering::SeqCst);
                return;
            }
            Ok(n) => {
                plain.extend_from_slice(&scratch[..n]);
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
        match tls.read_tls(&mut sock) {
            Ok(0) => return,
            Ok(_) => {
                if tls.process_new_packets().is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// The peer-side facts a responder records: how many connections it accepted,
/// and whether a TLS `close_notify` was observed on a served connection. The
/// alert is distinguished from a bare TCP FIN by which read reports the end:
/// the rustls reader returning `Ok(0)` records it, while `read_tls` returning
/// `Ok(0)` is the bare FIN and records nothing.
#[derive(Debug, Default)]
pub(crate) struct ResponderObservations {
    accepts: AtomicUsize,
    close_notify: AtomicBool,
}

/// A loopback TLS responder that accepts connections until dropped, completing
/// the rustls server handshake and answering each accepted connection's DNS
/// queries. The nonblocking accept loop with a stop flag lets the owning test
/// shut the thread down deterministically.
pub(crate) struct TlsResponder {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    observations: Arc<ResponderObservations>,
}

impl TlsResponder {
    pub(crate) fn port(&self) -> u16 {
        self.addr.port()
    }

    /// How many connections the peer accepted: a redial is observed at the
    /// peer, never by pointer identity, because a freed connection can be
    /// reallocated at the same address.
    pub(crate) fn accepts(&self) -> usize {
        self.observations.accepts.load(Ordering::SeqCst)
    }

    /// Whether the peer read a TLS `close_notify` on an accepted connection:
    /// the retirement's graceful close, as opposed to a bare TCP FIN.
    pub(crate) fn saw_close_notify(&self) -> bool {
        self.observations.close_notify.load(Ordering::SeqCst)
    }
}

impl Drop for TlsResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The per-connection driver for a spawned TLS responder: completes the
/// handshake (or performs post-handshake work) and serves the connection,
/// recording whatever peer-side fact it must observe into `observations`.
type ConnHandler = fn(TcpStream, &Arc<ServerConfig>, AdversarialReply, &ResponderObservations);

pub(crate) fn spawn_tls_responder(
    cert: &'static [u8],
    key: &'static [u8],
    mode: AdversarialReply,
) -> TlsResponder {
    spawn_tls_responder_with(
        Arc::new(server_config(cert, key)),
        mode,
        serve_conn_blocking,
    )
}

/// Spawns a TLS responder from a caller-built server configuration (e.g. a
/// protocol-version-restricted config).
fn spawn_tls_responder_config(config: ServerConfig, mode: AdversarialReply) -> TlsResponder {
    spawn_tls_responder_with(Arc::new(config), mode, serve_conn_blocking)
}

/// Spawns a TLS responder that forces a post-handshake traffic-key refresh
/// (`KeyUpdate`) on every accepted connection before serving queries.
fn spawn_tls_responder_post_handshake(
    config: ServerConfig,
    mode: AdversarialReply,
) -> TlsResponder {
    spawn_tls_responder_with(Arc::new(config), mode, serve_conn_blocking_post_handshake)
}

/// Spawns a TLS responder that records whether the client closed an accepted
/// connection with a `close_notify` alert. It answers queries positively like
/// the default responder, so a graceful close and a bare FIN stay the only
/// difference the owning test observes.
fn spawn_close_notify_responder(cert: &'static [u8], key: &'static [u8]) -> TlsResponder {
    spawn_tls_responder_with(
        Arc::new(server_config(cert, key)),
        AdversarialReply::Positive,
        serve_conn_blocking_observed,
    )
}

fn spawn_tls_responder_with(
    config: Arc<ServerConfig>,
    mode: AdversarialReply,
    handler: ConnHandler,
) -> TlsResponder {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls responder");
    listener
        .set_nonblocking(true)
        .expect("tls responder nonblocking");
    let addr = listener.local_addr().expect("tls responder addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let observations = Arc::new(ResponderObservations::default());
    let observed = Arc::clone(&observations);
    let handle = thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((sock, _)) => {
                    observed.accepts.fetch_add(1, Ordering::SeqCst);
                    if sock.set_nonblocking(false).is_ok() {
                        handler(sock, &config, mode, &observed);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });
    TlsResponder {
        addr,
        stop,
        handle: Some(handle),
        observations,
    }
}

/// A loopback responder that writes raw bytes on each accepted connection
/// without any TLS framing, holding the connection open until dropped. Used to
/// feed the transport an oversized handshake record that the rustls deframer
/// must reject ("message buffer full").
fn spawn_raw_responder(bytes: Vec<u8>) -> TlsResponder {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind raw responder");
    listener
        .set_nonblocking(true)
        .expect("raw responder nonblocking");
    let addr = listener.local_addr().expect("raw responder addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let observations = Arc::new(ResponderObservations::default());
    let observed = Arc::clone(&observations);
    let handle = thread::spawn(move || {
        let mut held: Vec<TcpStream> = Vec::new();
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    observed.accepts.fetch_add(1, Ordering::SeqCst);
                    let _ = sock.set_nonblocking(false);
                    let _ = sock.write_all(&bytes);
                    held.push(sock);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });
    TlsResponder {
        addr,
        stop,
        handle: Some(handle),
        observations,
    }
}

/// One scripted peer action for the query it receives, so a single retained
/// connection can behave differently per exchange — which the one-mode
/// responder cannot express.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PeerScript {
    /// A valid positive echo.
    Positive,
    /// A structurally valid message that is not a response (`QR=0`).
    Mangled,
    /// Write only the length prefix of a positive reply, then end the TCP
    /// stream without answering the rest.
    ClosedAfterPrefix,
    /// End the TCP stream without answering and hold the socket read, so the
    /// client observes a clean end of stream rather than a reset.
    CloseTcp,
    /// Send a `close_notify` and hold the socket open: the TLS session is over
    /// but the TCP stream never ends.
    HalfClose,
    /// Write non-TLS octets instead of a record.
    Garbage,
    /// Never answer and hold the socket open.
    Withhold,
    /// Answer after waiting.
    Late(Duration),
}

/// Spawns a TLS responder that serves each accepted connection from its own
/// script: entry `n` is the query script for the `n`th accepted connection,
/// with the last entry repeating. It lets a retained connection change
/// behaviour between exchanges without conflating a redial with the first
/// dial.
fn spawn_scripted_responder(
    cert: &'static [u8],
    key: &'static [u8],
    scripts: Vec<Vec<PeerScript>>,
) -> TlsResponder {
    let config = Arc::new(server_config(cert, key));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted responder");
    listener
        .set_nonblocking(true)
        .expect("scripted responder nonblocking");
    let addr = listener.local_addr().expect("scripted responder addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let observations = Arc::new(ResponderObservations::default());
    let observed = Arc::clone(&observations);
    let handle = thread::spawn(move || {
        let mut accepted = 0usize;
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((sock, _)) => {
                    let script = scripts
                        .get(accepted)
                        .or_else(|| scripts.last())
                        .cloned()
                        .unwrap_or_default();
                    accepted += 1;
                    observed.accepts.fetch_add(1, Ordering::SeqCst);
                    if sock.set_nonblocking(false).is_ok() {
                        serve_scripted_conn(sock, &config, &script);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });
    TlsResponder {
        addr,
        stop,
        handle: Some(handle),
        observations,
    }
}

/// Drives one scripted accepted connection: completes the server handshake,
/// then applies the script entry for each query, with the last entry repeating.
fn serve_scripted_conn(sock: TcpStream, config: &Arc<ServerConfig>, script: &[PeerScript]) {
    let mut sock = sock;
    let Ok(mut tls) = ServerConnection::new(Arc::clone(config)) else {
        return;
    };
    if tls.complete_io(&mut sock).is_err() {
        return;
    }
    let mut plain: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 4096];
    let mut served = 0usize;
    loop {
        if let Some(query) = take_framed_query(&mut plain) {
            let Some(step) = script.get(served).or_else(|| script.last()).copied() else {
                return;
            };
            served += 1;
            if !serve_scripted_step(&mut tls, &mut sock, step, &query) {
                return;
            }
            continue;
        }
        match drain_plaintext(&mut tls, &mut plain, &mut scratch) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => return,
        }
        if !read_more_tls(&mut tls, &mut sock) {
            return;
        }
    }
}

fn serve_scripted_step(
    tls: &mut ServerConnection,
    sock: &mut TcpStream,
    step: PeerScript,
    query: &[u8],
) -> bool {
    match step {
        PeerScript::Positive => write_tls_message(tls, sock, &echo_positive(query)).is_ok(),
        PeerScript::Mangled => write_tls_message(tls, sock, &mangled_reply(query)).is_ok(),
        PeerScript::ClosedAfterPrefix => {
            let reply = echo_positive(query);
            let prefix = u16::try_from(reply.len()).expect("reply fits u16");
            if tls.writer().write_all(&prefix.to_be_bytes()).is_err()
                || tls.writer().flush().is_err()
                || flush_tls(tls, sock).is_err()
            {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
            end_tcp_stream(sock)
        }
        PeerScript::CloseTcp => end_tcp_stream(sock),
        PeerScript::HalfClose => {
            tls.send_close_notify();
            let _ = flush_tls(tls, sock);
            hold_open(sock);
            false
        }
        PeerScript::Garbage => {
            let _ = sock.write_all(&[0xff; 8]);
            false
        }
        PeerScript::Withhold => {
            hold_open(sock);
            false
        }
        PeerScript::Late(delay) => {
            thread::sleep(delay);
            write_tls_message(tls, sock, &echo_positive(query)).is_ok()
        }
    }
}

/// Ends the TCP stream and keeps the socket read, so the client observes a
/// clean end of stream and its own later write is resolved instead of reset.
fn end_tcp_stream(sock: &mut TcpStream) -> bool {
    let _ = sock.shutdown(std::net::Shutdown::Write);
    hold_open(sock);
    false
}

/// Discards whatever the client sends until it closes, under a bounded wait so
/// a peer that never closes cannot wedge the responder thread.
fn hold_open(sock: &mut TcpStream) {
    let started = Instant::now();
    let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
    let mut scratch = [0u8; 256];
    loop {
        if started.elapsed() > Duration::from_secs(5) {
            return;
        }
        match sock.read(&mut scratch) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

#[test]
fn pinned_dot_resolver_resolves_both_names_over_loopback_tls() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
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
        report.resolved_names, 2,
        "a pin-matching DoT resolver must resolve the whole allowlist"
    );
    let name = cache.name_index(0).unwrap();
    let evidence = cache
        .entry(name, Family::A)
        .expect("entry")
        .evidence()
        .expect("real completed pinned TLS exchange binds reply-derived evidence to the cache");
    assert_eq!(
        evidence.source(),
        crate::dns::cache::evidence::ResolverSource::index(0).expect("primary index"),
        "the actual configured primary resolver used for this connection is the bound source"
    );
    assert!(
        evidence.origin_authenticated(),
        "a completed strict-pin TLS handshake authenticates the bound positive"
    );
    assert!(
        !evidence.raw_ad(),
        "the loopback fixture reply carries AD=0, witnessed as the raw reply fact"
    );
    assert_eq!(
        evidence.evidential_deadline(),
        Some(evidence.evidential_start() + 120),
        "the supporting TTL (120) from the real parsed reply anchors to the query-start floor"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    assert_eq!(
        transport.take_expired_pin_certs(),
        0,
        "an in-window pin-matching certificate must not raise the expired-pin warning"
    );
    drop(responder);
}

#[test]
fn pinned_dot_wrong_pin_fails_handshake_and_publishes_nothing() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(WRONG_PINNED_RESOLVER);
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
    assert_eq!(
        report.failed, 4,
        "every pinned exchange must fail the certificate pin comparison, never fall back to plain DNS"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 0, Family::Aaaa), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::Aaaa), Vec::new());
    match report.outcomes[0] {
        NameOutcome::Failed(reason) => assert_eq!(reason.as_str(), "pin_mismatch"),
        _ => panic!("wrong-pin exchange must conclude as a failed name outcome"),
    }
    assert!(
        cache
            .entry(cache.name_index(0).unwrap(), Family::A)
            .unwrap()
            .evidence()
            .is_none(),
        "a wrong-pin handshake failure publishes no authenticated evidence"
    );
    drop(responder);
}

#[test]
fn pinned_dot_san_mismatch_fails_identity_and_publishes_nothing() {
    let responder = spawn_tls_responder(SAN_MISMATCH_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
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
    assert_eq!(
        report.failed, 4,
        "a pin-matching certificate whose SAN does not name the resolver fqdn must be rejected"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 0, Family::Aaaa), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::Aaaa), Vec::new());
    match report.outcomes[0] {
        NameOutcome::Failed(reason) => assert_eq!(reason.as_str(), "san_mismatch"),
        _ => panic!("SAN-mismatch exchange must conclude as a failed name outcome"),
    }
    drop(responder);
}

#[test]
fn unpinned_dot_with_empty_root_store_rejects_self_signed_and_publishes_nothing() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(UNPINNED_RESOLVER);
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
    assert_eq!(
        report.failed, 4,
        "an unpinned DoT entry validates against the empty root store; a self-signed cert deterministically fails closed"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    match report.outcomes[0] {
        NameOutcome::Failed(reason) => assert_eq!(reason.as_str(), "no_anchor"),
        _ => panic!("empty-root exchange must conclude as a failed name outcome"),
    }
    drop(responder);
}

#[test]
fn dot_wrong_tid_reply_fails_closed_over_tls() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::WrongTid);
    let cfg = dot_config(&pinned_resolver());
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
    assert_eq!(
        report.failed, 4,
        "a reply whose transaction id differs from the query must fail every pinned exchange closed"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 0, Family::Aaaa), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::Aaaa), Vec::new());
    drop(responder);
}

#[test]
fn dot_oversize_reply_fails_closed_over_tls() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Oversize);
    let cfg = dot_config(&pinned_resolver());
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
    assert_eq!(
        report.failed, 4,
        "a reply length prefix over DNS_MSG_LIMIT must fail every pinned exchange closed"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 0, Family::Aaaa), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::Aaaa), Vec::new());
    drop(responder);
}

#[test]
fn dot_mangled_reply_fails_closed_over_tls() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Mangled);
    let cfg = dot_config(&pinned_resolver());
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
    assert_eq!(
        report.failed, 4,
        "a non-response (QR=0) reply must fail every pinned exchange closed"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 0, Family::Aaaa), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::Aaaa), Vec::new());
    drop(responder);
}

#[test]
fn dot_exchange_traverses_handshake_before_send_and_receive() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.start_family_a(fqdn, 0, deadline);
    let mut seen: Vec<ExchangeStep> = Vec::new();
    let mut handshake_seen: Option<usize> = None;
    let terminal = dot.drive_observed(fqdn, deadline, |transport, step| {
        if step == ExchangeStep::TlsHandshake && handshake_seen.is_none() {
            handshake_seen = Some(seen.len());
        }
        if matches!(step, ExchangeStep::SendReady | ExchangeStep::Receiving) {
            let is_tls = matches!(&transport.conn, Some(DnsConn::Tls(_)));
            let is_handshaking = matches!(
                &transport.conn,
                Some(DnsConn::Tls(conn)) if conn.tls.is_handshaking()
            );
            assert!(
                is_tls && !is_handshaking,
                "DoT crypto must be fully verified before the query is sent or a response is received: step={step:?} at boundary index {}, seen={seen:?}, conn_is_tls={is_tls}, is_handshaking={is_handshaking}",
                seen.len()
            );
        }
        seen.push(step);
    });
    assert!(
        matches!(terminal, Some(TurnResult::Published(_))),
        "a pin-matching DoT exchange must publish at the primitive level, got {terminal:?}"
    );
    let at = |step: ExchangeStep| seen.iter().position(|&candidate| candidate == step);
    let send_ready = at(ExchangeStep::SendReady).expect("the send stage must be observed");
    let receiving = at(ExchangeStep::Receiving).expect("the receive stage must be observed");
    assert!(
        send_ready < receiving,
        "the query must be sent before the response is received: {seen:?}"
    );
    if let Some(handshake_seen) = handshake_seen {
        assert!(
            handshake_seen < send_ready,
            "when the TLS handshake stage is observed it must precede the send stage: {seen:?}"
        );
    }
    assert_eq!(
        bindings_of(&dot.cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    dot.transport.close_connection().unwrap();
    drop(responder);
}

/// Drives a shared-mode exchange to a terminal turn through an external
/// single-poll owner, mirroring the serving owner's cooperative loop: each
/// turn re-aligns the shared registration to the exchange phase, waits on the
/// external poll only when the exchange needs network readiness, and
/// re-advances until the exchange concludes.
fn drive_to_terminal(
    transport: &mut StartupDns,
    cache: &mut Cache,
    schedules: &mut Schedules,
    fqdn: &Fqdn,
    deadline: Instant,
    poll: &mut Poll,
    events: &mut Events,
) -> TurnResult {
    drive_to_terminal_observed(
        transport,
        cache,
        schedules,
        fqdn,
        deadline,
        (poll, events),
        |_| {},
    )
}

/// The longest the harness owner blocks in one poll. A serving owner re-advances
/// a cooperative exchange on its own cadence, so the harness never depends on a
/// peer close producing a readiness edge in order to make progress.
const OWNER_TURN_SLICE: Duration = Duration::from_millis(20);

/// [`drive_to_terminal`] with a per-turn observer over the live transport, so a
/// case can record a fact the concluded exchange no longer exposes — such as
/// the exchange deadline it never renewed.
fn drive_to_terminal_observed(
    transport: &mut StartupDns,
    cache: &mut Cache,
    schedules: &mut Schedules,
    fqdn: &Fqdn,
    deadline: Instant,
    (poll, events): (&mut Poll, &mut Events),
    mut observe: impl FnMut(&StartupDns),
) -> TurnResult {
    loop {
        observe(transport);
        match transport
            .advance_exchange(fqdn, cache, schedules)
            .expect("a live shared-registration DoT exchange advances without a fatal error")
        {
            TurnResult::Pending => {}
            terminal => return terminal,
        }
        transport
            .sync_shared(poll.registry())
            .expect("shared registration stays aligned");
        if !transport.needs_wait() {
            continue;
        }
        let until = transport
            .exchange_deadline()
            .unwrap_or(deadline)
            .min(deadline);
        let now = Instant::now();
        if now >= until {
            continue;
        }
        let wait = (until - now).min(OWNER_TURN_SLICE);
        poll.poll(events, Some(wait)).expect("external poll wait");
    }
}

#[test]
fn serving_refresh_retains_dot_transport_without_rebuild() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.start_family_a(fqdn, 0, deadline);
    let first = dot.drive_shared(fqdn, deadline, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first serving-refresh exchange must publish, got {first:?}"
    );
    assert!(
        dot.transport.conn.is_some(),
        "a concluded serving-refresh exchange must retain its DoT transport for the next refresh"
    );
    let first_addr = match dot.transport.conn.as_ref().expect("retained DoT transport") {
        DnsConn::Tls(conn) => &*conn.tls as *const _,
        DnsConn::Plain { .. } => panic!("a pinned DoT exchange must retain a TLS transport"),
    };
    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.start_family_a(fqdn, 1, deadline);
    let second = dot.drive_shared(fqdn, deadline, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Published(_)),
        "the second serving-refresh exchange must publish over the retained transport, got {second:?}"
    );
    let second_addr = match dot.transport.conn.as_ref().expect("retained DoT transport") {
        DnsConn::Tls(conn) => &*conn.tls as *const _,
        DnsConn::Plain { .. } => panic!("a pinned DoT exchange must retain a TLS transport"),
    };
    assert!(
        std::ptr::addr_eq(first_addr, second_addr),
        "the serving refresh must reuse the same rustls client allocation, not rebuild it"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn pinned_dot_accepts_expired_cert_with_matching_pin() {
    let responder = spawn_tls_responder(EXPIRED_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
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
        report.resolved_names, 2,
        "the pinned verifier checks only SAN plus SPKI pin, never certificate validity, so an expired cert must still resolve"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    assert_eq!(
        transport.take_expired_pin_certs(),
        1,
        "the pin-matching expired certificate must raise exactly one expired-pin warning"
    );
    drop(responder);
}

#[test]
fn pinned_dot_accepts_not_yet_valid_cert_with_matching_pin() {
    let responder = spawn_tls_responder(NOT_YET_VALID_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
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
        report.resolved_names, 2,
        "the pinned verifier checks only SAN plus SPKI pin, never certificate validity, so a not-yet-valid cert must still resolve"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    assert_eq!(
        transport.take_expired_pin_certs(),
        1,
        "the pin-matching not-yet-valid certificate must raise exactly one expired-pin warning"
    );
    drop(responder);
}

#[test]
fn pinned_dot_rejects_tls12_only_peer() {
    // A TLS 1.2-only server answers a ClientHello offering only TLS 1.3 with a
    // fatal `protocol_version` alert (0x46). The transport's rustls client has
    // no TLS 1.2 code at all (the `tls12` feature is removed), so this is the
    // closest honest byte-level stand-in for that peer: the client must fail
    // closed on the alert, never fall back to plain DNS.
    let responder = spawn_raw_responder(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46]);
    let cfg = dot_config(&pinned_resolver());
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
    assert_eq!(
        report.failed, 4,
        "the TLS 1.3-only DoT client must refuse a peer that cannot complete a TLS 1.3 handshake, never negotiate down"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 0, Family::Aaaa), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::Aaaa), Vec::new());
    drop(responder);
}

#[test]
fn pinned_dot_negotiates_tls13_with_tls13_only_server() {
    let responder = spawn_tls_responder_config(
        server_config_tls13(GOOD_CERT, GOOD_KEY),
        AdversarialReply::Positive,
    );
    let cfg = dot_config(&pinned_resolver());
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
        report.resolved_names, 2,
        "the TLS 1.3-only DoT client must negotiate TLS 1.3 with a TLS 1.3-only server and publish"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    drop(responder);
}

#[test]
fn unpinned_dot_rejects_tls12_only_peer() {
    // Same TLS 1.2 `protocol_version` fatal alert on the CA-chain branch: the
    // client must fail closed at the handshake before any cert check runs.
    let responder = spawn_raw_responder(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46]);
    let cfg = dot_config(UNPINNED_RESOLVER);
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
    assert_eq!(
        report.failed, 4,
        "the TLS 1.3-only DoT client must refuse a peer that cannot complete a TLS 1.3 handshake on the CA-chain branch too"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    drop(responder);
}

#[test]
fn pinned_dot_oversized_handshake_record_fails_closed() {
    let mut raw = vec![0x16, 0x03, 0x03, 0xff, 0xff];
    raw.extend(std::iter::repeat_n(0u8, 0xffff));
    let responder = spawn_raw_responder(raw);
    let cfg = dot_config(&pinned_resolver());
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
    assert_eq!(
        report.failed, 4,
        "an oversized handshake record must overflow the rustls deframer and fail every exchange closed"
    );
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.resolved_names, 0);
    assert_eq!(bindings_of(&cache, 0, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 0, Family::Aaaa), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::A), Vec::new());
    assert_eq!(bindings_of(&cache, 1, Family::Aaaa), Vec::new());
    drop(responder);
}

#[test]
fn pinned_dot_post_handshake_records_do_not_break_exchange() {
    let responder = spawn_tls_responder_post_handshake(
        server_config(GOOD_CERT, GOOD_KEY),
        AdversarialReply::Positive,
    );
    let cfg = dot_config(&pinned_resolver());
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
        report.resolved_names, 2,
        "post-handshake KeyUpdate and session-ticket records must be processed as non-application data without breaking the exchange"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    drop(responder);
}

#[test]
fn pinned_dot_reply_split_across_records_drains_and_publishes() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::SplitRecord);
    let cfg = dot_config(&pinned_resolver());
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
        report.resolved_names, 2,
        "a reply split across two TLS records must drain one plaintext chunk per turn and still publish the assembled message"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    drop(responder);
}

#[test]
fn reused_connection_clean_eof_is_retired_once() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![
            vec![PeerScript::Positive, PeerScript::CloseTcp],
            vec![PeerScript::Positive],
        ],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    transport.resolvers = Some(*cfg.resolver_set());
    transport.active_resolver = ActiveResolver::primary_of(cfg.resolver_set());
    transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
        fqdn: *fqdn,
        pin: cfg.resolver_set().primary().pin().copied(),
    });
    transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let deadline = Instant::now() + Duration::from_millis(1500);
    super::tests::start_startup_exchange(&mut transport, fqdn, 0, deadline);
    let first = drive_to_terminal(
        &mut transport,
        &mut cache,
        &mut schedules,
        fqdn,
        deadline,
        &mut poll,
        &mut events,
    );
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange over a live connection must publish, got {first:?}"
    );
    assert!(
        transport.conn.is_some(),
        "a concluded exchange must retain its DoT transport for the next exchange"
    );
    assert_eq!(responder.accepts(), 1, "one dial serves the first exchange");

    let deadline = Instant::now() + Duration::from_millis(1500);
    super::tests::start_startup_exchange(&mut transport, fqdn, 1, deadline);
    let second = drive_to_terminal(
        &mut transport,
        &mut cache,
        &mut schedules,
        fqdn,
        deadline,
        &mut poll,
        &mut events,
    );
    assert!(
        matches!(second, TurnResult::Published(_)),
        "a clean peer close before any reply octet must retire the retained transport and restart the same exchange once on a fresh connection, so the second exchange publishes instead of failing closed, got {second:?}"
    );
    assert_eq!(
        responder.accepts(),
        2,
        "the silent retirement redials exactly once"
    );
    assert!(
        transport.last_failed[1][0].is_none(),
        "the retired exchange counts no failure, so no backoff advances and no resolver is blamed"
    );
    assert_eq!(
        transport.incident_opens, 0,
        "the retired exchange opens no incident"
    );
    let evidence = cache
        .entry(cache.name_index(0).unwrap(), Family::A)
        .unwrap()
        .evidence()
        .expect("the first published proof survives the retirement");
    assert!(
        evidence.origin_authenticated(),
        "the published proof is authenticated, never weakened by the retirement"
    );
    transport.cancel_for_shutdown();
    drop(responder);
}

/// Publishes exchange `ordinal` over the loopback responder through the shared
/// owner's cooperative loop, so every idle-retire case observes the same
/// retained-connection baseline.
fn publish_exchange(
    dot: &mut DotExchange,
    fqdn: &Fqdn,
    ordinal: usize,
    poll: &mut Poll,
    events: &mut Events,
) -> TurnResult {
    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.start_family_a(fqdn, ordinal, deadline);
    dot.drive_shared(fqdn, deadline, poll, events)
}

/// The rustls client allocation a retained `DoT` transport holds, so a case can
/// prove the very same connection object was reused.
fn retained_tls(dot: &DotExchange) -> *const ClientConnection {
    match dot.transport.conn.as_ref().expect("retained DoT transport") {
        DnsConn::Tls(conn) => &*conn.tls as *const _,
        DnsConn::Plain { .. } => panic!("a pinned DoT exchange must retain a TLS transport"),
    }
}

/// A two-entry `DoT` resolver set whose primary is the pinned loopback identity
/// and whose backup shares the FQDN, so a failback probe is a same-form
/// relocation with no downgrade to count.
fn two_dot_resolvers() -> ResolverSet {
    let primary = crate::dns::resolver::select(&pinned_resolver()).expect("primary dot entry");
    let backup =
        crate::dns::resolver::select(&format!("127.0.0.2#{DOT_FQDN}")).expect("backup dot entry");
    ResolverSet::from_slice(&[primary, backup]).expect("two DoT entries fit the resolver bound")
}

#[test]
fn idle_connection_beyond_the_bound_is_retired_and_redialled() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish over the dialed connection, got {first:?}"
    );
    assert_eq!(responder.accepts(), 1, "one dial serves the first exchange");
    assert!(
        dot.transport.last_used.is_some(),
        "a concluded exchange that kept its connection records when it was last used"
    );

    dot.transport.last_used = Some(Instant::now() - Duration::from_secs(20));
    let second = publish_exchange(&mut dot, fqdn, 1, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Published(_)),
        "the retired-then-redialled exchange must publish, got {second:?}"
    );
    assert_eq!(
        responder.accepts(),
        2,
        "a retained DoT connection past the idle bound is retired before reuse, so the next exchange dials fresh instead of writing to a socket the peer may have closed"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn retained_connection_without_recorded_use_is_retired() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish over the dialed connection, got {first:?}"
    );

    dot.transport.last_used = None;
    let second = publish_exchange(&mut dot, fqdn, 1, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Published(_)),
        "the exchange that replaced an unrecorded retained connection must publish, got {second:?}"
    );
    assert_eq!(
        responder.accepts(),
        2,
        "a retained connection with no recorded use may be an arbitrary age, so it is retired and redialled"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn retirement_sends_close_notify() {
    let responder = spawn_close_notify_responder(GOOD_CERT, GOOD_KEY);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish over the dialed connection, got {first:?}"
    );
    assert!(
        !responder.saw_close_notify(),
        "a retained connection is not closed by its exchange, so the peer has seen no alert yet"
    );

    dot.transport.last_used = Some(Instant::now() - Duration::from_secs(20));
    let second = publish_exchange(&mut dot, fqdn, 1, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Published(_)),
        "the exchange over the fresh connection must publish, got {second:?}"
    );
    assert_eq!(responder.accepts(), 2, "the retirement redials");
    assert!(
        responder.saw_close_notify(),
        "the retirement ends the TLS session with a close_notify alert, not a bare TCP FIN"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn idle_retire_is_skipped_when_residual_is_small() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish over the dialed connection, got {first:?}"
    );
    let retained = retained_tls(&dot);

    dot.transport.last_used = Some(Instant::now() - Duration::from_secs(20));
    let deadline = Instant::now() + Duration::from_millis(800);
    dot.start_family_a(fqdn, 1, deadline);
    assert_eq!(
        responder.accepts(),
        1,
        "a retirement that could not complete its dial inside the exchange deadline is skipped, leaving the counted failure as the honest outcome"
    );
    let second = dot.drive_shared(fqdn, deadline, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Published(_)),
        "the retained connection still serves the exchange, got {second:?}"
    );
    assert!(
        std::ptr::addr_eq(retained, retained_tls(&dot)),
        "the skip leaves the very same retained connection in place"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn failback_then_idle_retire_closes_once() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let set = two_dot_resolvers();
    dot.transport.resolvers = Some(set);
    dot.transport.active_resolver = ActiveResolver::primary_of(&set);
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish over the dialed connection, got {first:?}"
    );
    assert_eq!(responder.accepts(), 1, "one dial serves the first exchange");

    dot.transport.active_resolver = ActiveResolver::primary_of(&set)
        .with_index(1)
        .expect("the backup seat is in range");
    dot.transport.failback_due = Some(dot.transport.now_u64());
    dot.transport.last_used = Some(Instant::now() - Duration::from_secs(20));
    dot.transport
        .maybe_begin_failback()
        .expect("the failback close is the single close of the retained connection");
    assert!(
        dot.transport.conn.is_none() && dot.transport.last_used.is_none(),
        "the failback closes the retained connection before repointing, so no stale retention state survives it"
    );
    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.transport.retire_stale_idle_connection(deadline).expect(
        "the idle retire on the already-closed connection is a no-op, never a double close",
    );
    assert_eq!(
        responder.accepts(),
        1,
        "the failback close is the only close: the idle retire adds no dial and no second connection"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn idle_retire_touches_no_attempt_or_incident() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish over the dialed connection, got {first:?}"
    );
    let before = (
        dot.schedules.due_time(0, Family::A).expect("due in range"),
        dot.schedules.incident(0, Family::A),
        dot.transport.last_failed[0][0],
        dot.transport.resolver_transitions,
        dot.transport.incident_opens,
        dot.transport.incident_closes,
        dot.transport.dns_anomalies,
        dot.transport.failback_due,
    );

    dot.transport.last_used = Some(Instant::now() - Duration::from_secs(20));
    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.transport
        .retire_stale_idle_connection(deadline)
        .expect("the idle retire closes the connection");
    let after = (
        dot.schedules.due_time(0, Family::A).expect("due in range"),
        dot.schedules.incident(0, Family::A),
        dot.transport.last_failed[0][0],
        dot.transport.resolver_transitions,
        dot.transport.incident_opens,
        dot.transport.incident_closes,
        dot.transport.dns_anomalies,
        dot.transport.failback_due,
    );
    assert_eq!(
        before, after,
        "retiring an idle connection advances no attempt, failure, backoff, degradation, or incident state"
    );
    assert!(
        dot.transport.conn.is_none(),
        "the retired connection is gone"
    );

    let second = publish_exchange(&mut dot, fqdn, 1, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Published(_)),
        "the redialled exchange after the retire must publish, got {second:?}"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn retirement_never_runs_under_a_live_exchange() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish over the dialed connection, got {first:?}"
    );
    let retained = retained_tls(&dot);

    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.start_family_a(fqdn, 1, deadline);
    let live = dot
        .transport
        .advance_exchange(fqdn, &mut dot.cache, &mut dot.schedules)
        .expect("the live exchange takes its first turn");
    assert!(
        matches!(live, TurnResult::Pending),
        "the live exchange is still in progress, got {live:?}"
    );

    dot.transport.last_used = Some(Instant::now() - Duration::from_secs(20));
    let refused = dot
        .transport
        .start_exchange(
            fqdn,
            Family::A,
            0,
            deadline,
            Generation::INITIAL,
            ExchangeClass::Startup,
        )
        .expect_err("a start over a live exchange is refused before anything is touched");
    assert_eq!(
        refused,
        StartupDnsError::ExchangeActive,
        "the live-exchange guard is the typed refusal, not a silent retire of the live socket"
    );
    assert_eq!(
        responder.accepts(),
        1,
        "the refusal retires nothing and dials nothing"
    );
    assert!(
        std::ptr::addr_eq(retained, retained_tls(&dot)),
        "the refused start leaves the live exchange's connection untouched"
    );

    let concluded = dot.drive_shared(fqdn, deadline, &mut poll, &mut events);
    assert!(
        matches!(concluded, TurnResult::Published(_)),
        "the live exchange still concludes over its connection, got {concluded:?}"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

/// Publishes exchange `ordinal` over the loopback responder, then reports the
/// retained connection's next exchange.
fn second_exchange_over_retained(
    dot: &mut DotExchange,
    fqdn: &Fqdn,
    poll: &mut Poll,
    events: &mut Events,
) -> TurnResult {
    publish_exchange(dot, fqdn, 1, poll, events)
}

/// Drives one exchange on a two-second budget and reports how long it took, so
/// a case can prove the conclusion landed while the retirement residual was
/// still available — leaving only the gate under test to explain it.
fn timed_exchange(
    dot: &mut DotExchange,
    fqdn: &Fqdn,
    ordinal: usize,
    poll: &mut Poll,
    events: &mut Events,
) -> (TurnResult, Duration) {
    let deadline = Instant::now() + Duration::from_millis(2000);
    let started = Instant::now();
    dot.start_family_a(fqdn, ordinal, deadline);
    let result = dot.drive_shared(fqdn, deadline, poll, events);
    (result, started.elapsed())
}

/// The elapsed bound that proves a failed exchange concluded with more than
/// `RETIRE_MIN_RESIDUAL` left, so the residual gate could not have decided it.
const PROMPT_CONCLUSION: Duration = Duration::from_millis(1000);

#[test]
fn retire_is_bounded_to_one_per_exchange() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![
            vec![PeerScript::Positive, PeerScript::CloseTcp],
            vec![PeerScript::CloseTcp],
        ],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let (second, elapsed) = timed_exchange(&mut dot, fqdn, 1, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Receive)),
        "the replacement connection closing cleanly before any reply octet spends the exchange's single retirement budget, so the second clean EOF is counted, got {second:?}"
    );
    assert!(
        elapsed < PROMPT_CONCLUSION,
        "the second clean EOF was concluded with the retirement residual still available ({elapsed:?}), so only the spent retirement budget can explain the counted failure"
    );
    assert_eq!(
        responder.accepts(),
        2,
        "one retire, one redial: the counted second failure dials no third connection"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn reused_connection_tls_error_is_counted() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![PeerScript::Positive, PeerScript::Garbage]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let (second, elapsed) = timed_exchange(&mut dot, fqdn, 1, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Receive)),
        "non-TLS octets on a reused connection are a protocol fault, never a clean end of stream, so the failure is counted, got {second:?}"
    );
    assert!(
        elapsed < PROMPT_CONCLUSION,
        "the fault was concluded with the retirement residual still available ({elapsed:?}), so only the unclean end of stream can explain the counted failure"
    );
    assert_eq!(
        responder.accepts(),
        1,
        "a counted protocol fault retires nothing and dials nothing"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn reused_connection_malformed_reply_is_counted() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![PeerScript::Positive, PeerScript::Mangled]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let second = second_exchange_over_retained(&mut dot, fqdn, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Receive)),
        "a full but unparseable reply is counted, got {second:?}"
    );
    assert!(
        dot.transport.reply_octets > 0,
        "the peer answered with reply octets, so the retirement predicate must not apply"
    );
    assert_eq!(responder.accepts(), 1, "a malformed reply dials nothing");
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn reused_connection_late_reply_is_counted() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![
            PeerScript::Positive,
            PeerScript::Late(Duration::from_millis(600)),
        ]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let deadline = Instant::now() + Duration::from_millis(300);
    dot.start_family_a(fqdn, 1, deadline);
    let second = dot.drive_shared(fqdn, deadline, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Timeout)),
        "a reply past the exchange deadline is counted, never awaited on a second budget, got {second:?}"
    );
    assert_eq!(responder.accepts(), 1, "a counted timeout dials nothing");
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn reused_connection_timeout_is_counted() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![PeerScript::Positive, PeerScript::Withhold]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let deadline = Instant::now() + Duration::from_millis(300);
    dot.start_family_a(fqdn, 1, deadline);
    let mut budgets = Vec::new();
    let second = drive_to_terminal_observed(
        &mut dot.transport,
        &mut dot.cache,
        &mut dot.schedules,
        fqdn,
        deadline,
        (&mut poll, &mut events),
        |transport| budgets.push(transport.exchange_deadline()),
    );
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Timeout)),
        "a silent peer is a counted timeout, got {second:?}"
    );
    assert!(
        !budgets.is_empty() && budgets.iter().all(|budget| *budget == Some(deadline)),
        "the counted timeout spends the one exchange deadline and is granted no second budget: {budgets:?}"
    );
    assert_eq!(responder.accepts(), 1, "a counted timeout dials nothing");
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn retire_skipped_when_residual_deadline_is_small() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![PeerScript::Positive, PeerScript::CloseTcp]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let deadline = Instant::now() + Duration::from_millis(900);
    dot.start_family_a(fqdn, 1, deadline);
    let second = dot.drive_shared(fqdn, deadline, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Receive)),
        "a retirement that could not finish its dial inside the remaining deadline is skipped, leaving the counted failure as the honest outcome, got {second:?}"
    );
    assert_eq!(
        responder.accepts(),
        1,
        "the skipped retirement dials nothing"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn peer_close_mid_burst_is_still_a_counted_failure() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![PeerScript::Positive, PeerScript::ClosedAfterPrefix]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let (second, elapsed) = timed_exchange(&mut dot, fqdn, 1, &mut poll, &mut events);
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Receive)),
        "a peer that closed after part of a reply is a counted failure, got {second:?}"
    );
    assert!(
        dot.transport.reply_octets > 0,
        "the partial frame's octets were absorbed, so the clean close is not a stale retirement"
    );
    assert!(
        elapsed < PROMPT_CONCLUSION,
        "the clean end of stream was concluded with the retirement residual still available ({elapsed:?}), so only the absorbed reply octets can explain the counted failure"
    );
    assert_eq!(responder.accepts(), 1, "a mid-burst close dials nothing");
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn retire_never_runs_for_probe_class() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![PeerScript::Positive, PeerScript::CloseTcp]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let deadline = Instant::now() + Duration::from_millis(2000);
    let started = Instant::now();
    dot.transport
        .start_exchange(
            fqdn,
            Family::A,
            1,
            deadline,
            Generation::INITIAL,
            ExchangeClass::Probe,
        )
        .expect("a probe may start on the retained connection");
    let second = drive_to_terminal(
        &mut dot.transport,
        &mut dot.cache,
        &mut dot.schedules,
        fqdn,
        deadline,
        &mut poll,
        &mut events,
    );
    assert!(
        matches!(second, TurnResult::Failed(FailureReason::Receive)),
        "a probe-class clean EOF is counted by class, never silently retired, got {second:?}"
    );
    assert!(
        started.elapsed() < PROMPT_CONCLUSION,
        "the probe's clean EOF was concluded with the retirement residual still available, so only the exchange class can explain the counted failure"
    );
    assert_eq!(
        responder.accepts(),
        1,
        "the probe's clean EOF dials nothing"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

#[test]
fn half_closed_reused_connection_times_out() {
    let responder = spawn_scripted_responder(
        GOOD_CERT,
        GOOD_KEY,
        vec![vec![PeerScript::Positive, PeerScript::HalfClose]],
    );
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    dot.transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let first = publish_exchange(&mut dot, fqdn, 0, &mut poll, &mut events);
    assert!(
        matches!(first, TurnResult::Published(_)),
        "the first exchange must publish, got {first:?}"
    );

    let deadline = Instant::now() + Duration::from_millis(300);
    dot.start_family_a(fqdn, 1, deadline);
    let mut budgets = Vec::new();
    let second = drive_to_terminal_observed(
        &mut dot.transport,
        &mut dot.cache,
        &mut dot.schedules,
        fqdn,
        deadline,
        (&mut poll, &mut events),
        |transport| budgets.push(transport.exchange_deadline()),
    );
    assert!(
        matches!(second, TurnResult::Failed(_)),
        "an ended TLS session over a live TCP stream must conclude as a counted failure, never publish, got {second:?}"
    );
    assert!(
        !budgets.is_empty() && budgets.iter().all(|budget| *budget == Some(deadline)),
        "the exchange spends its one deadline and is granted no second budget: {budgets:?}"
    );
    assert_eq!(
        responder.accepts(),
        1,
        "the stale retire never fires and dials nothing"
    );
    dot.transport.cancel_for_shutdown();
    drop(responder);
}

/// Calibrated upper bound on allocation events during one warm `DoT` exchange:
/// the transport itself must not allocate, while the bounded rustls seam may
/// allocate a small number of per-record buffers (§Zero-Allocation Invariant).
#[cfg(feature = "alloc-witness")]
const WARM_DOT_ALLOC_BOUND: u64 = 8;

#[cfg(feature = "alloc-witness")]
fn assert_evidence_identity(evidence: crate::dns::cache::evidence::Evidence, ordinal: usize) {
    assert_eq!(
        evidence.source(),
        crate::dns::cache::evidence::ResolverSource::index(0).expect("primary source"),
        "exchange {ordinal} binds the actual configured primary resolver source"
    );
    assert!(
        evidence.origin_authenticated(),
        "exchange {ordinal} is authenticated by completed strict-pin TLS"
    );
    assert!(
        !evidence.raw_ad(),
        "exchange {ordinal} carries AD=0 witnessed raw, never fabricated"
    );
    assert!(
        !evidence.qualified(),
        "exchange {ordinal} AD=0 evidence is never qualified"
    );
    assert_eq!(
        evidence.evidential_deadline(),
        Some(evidence.evidential_start() + 120),
        "exchange {ordinal} supporting TTL (120) anchors to the query-start floor"
    );
}

#[cfg(feature = "alloc-witness")]
#[test]
fn dot_warm_serving_exchange_alloc_witness() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    transport.resolvers = Some(*cfg.resolver_set());
    transport.active_resolver = ActiveResolver::primary_of(cfg.resolver_set());
    transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
        fqdn: *fqdn,
        pin: cfg.resolver_set().primary().pin().copied(),
    });
    transport.registration = Registration::shared(Token(0));
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    // Cold exchange: builds the rustls client and completes the handshake
    // outside the measured phase, so the warm path below is the only
    // allocation surface under witness.
    let deadline = Instant::now() + Duration::from_millis(1500);
    super::tests::start_startup_exchange(&mut transport, fqdn, 0, deadline);
    let cold = drive_to_terminal(
        &mut transport,
        &mut cache,
        &mut schedules,
        fqdn,
        deadline,
        &mut poll,
        &mut events,
    );
    assert!(
        matches!(cold, TurnResult::Published(_)),
        "the cold DoT exchange must publish, got {cold:?}"
    );
    assert_evidence_identity(
        cache
            .entry(cache.name_index(0).unwrap(), Family::A)
            .expect("cold entry")
            .evidence()
            .expect("the cold DoT exchange binds source evidence to index 0"),
        0,
    );
    assert!(
        transport.conn.is_some(),
        "a concluded DoT exchange must retain its transport for the warm reuse"
    );

    // Warm exchange over the retained transport: the rustls seam may allocate
    // a small bounded number of per-record buffers; the transport itself must
    // not allocate, so reallocs stay zero and total events stay within the
    // calibrated rustls seam bound.
    let deadline = Instant::now() + Duration::from_millis(1500);
    super::tests::start_startup_exchange(&mut transport, fqdn, 1, deadline);
    let (warm, counts) = crate::alloc::run_phase(crate::alloc::Phase::Serving, || {
        drive_to_terminal(
            &mut transport,
            &mut cache,
            &mut schedules,
            fqdn,
            deadline,
            &mut poll,
            &mut events,
        )
    });
    assert!(
        matches!(warm, TurnResult::Published(_)),
        "the warm DoT exchange must publish over the retained transport, got {warm:?}"
    );
    assert_eq!(
        counts.reallocs, 0,
        "the warm DoT exchange must not reallocate any transport buffer: {counts:?}"
    );
    assert!(
        counts.allocs <= WARM_DOT_ALLOC_BOUND && counts.deallocs <= WARM_DOT_ALLOC_BOUND,
        "the warm DoT exchange must stay within the calibrated rustls seam bound: {counts:?}"
    );
    assert_evidence_identity(
        cache
            .entry(cache.name_index(1).unwrap(), Family::A)
            .expect("warm entry")
            .evidence()
            .expect("the warm DoT exchange binds source evidence to index 1"),
        1,
    );
    transport.cancel_for_shutdown();
    drop(responder);
}

/// A fresh `DoT` client connection whose buffered `ClientHello` gives the
/// send helpers ciphertext to flush into a scripted sink, with no socket I/O.
fn buffered_tls_client() -> ClientConnection {
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("loopback client protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(DOT_FQDN.to_string()).expect("dot.test server name"),
    )
    .expect("buffered client connection")
}

/// One scripted socket `write` result for the bounded-send seam.
#[derive(Clone, Copy)]
enum SinkStep {
    Interrupted,
    WouldBlock,
    NoProgress,
    Partial(usize),
    Full,
}

/// Replays a fixed outcome script, panicking when over-called so a regression
/// to unbounded TLS-send retrying aborts the test instead of hanging.
struct ScriptedSink {
    script: Vec<SinkStep>,
    calls: usize,
}

impl ScriptedSink {
    fn new(script: Vec<SinkStep>) -> Self {
        Self { script, calls: 0 }
    }
}

impl io::Write for ScriptedSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        assert!(
            self.calls < self.script.len(),
            "scripted sink over-called ({}/{})",
            self.calls,
            self.script.len()
        );
        let step = self.script[self.calls];
        self.calls += 1;
        match step {
            SinkStep::Interrupted => Err(io::ErrorKind::Interrupted.into()),
            SinkStep::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            SinkStep::NoProgress => Ok(0),
            SinkStep::Partial(n) => Ok(n.min(buf.len())),
            SinkStep::Full => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn storm() -> Vec<SinkStep> {
    vec![SinkStep::Interrupted; (TLS_SEND_TRIES as usize) * 2]
}

/// A storm of the given outcome stops at exactly [`TLS_SEND_TRIES`] attempts
/// and defers, never looping.
fn drain_defers(conn: &mut ClientConnection, script: Vec<SinkStep>) {
    let mut sink = ScriptedSink::new(script);
    let out = drain_tls_write(&mut sink, conn).expect("deferral, never an error");
    assert!(matches!(out, TlsDrain::Deferred), "deferred: {out:?}");
    assert_eq!(sink.calls, TLS_SEND_TRIES as usize, "fixed allowance");
}

#[test]
fn drain_eintr_storm_and_no_progress_defer_after_fixed_attempts() {
    drain_defers(&mut buffered_tls_client(), storm());
    drain_defers(
        &mut buffered_tls_client(),
        vec![SinkStep::NoProgress; (TLS_SEND_TRIES as usize) * 2],
    );
}

#[test]
fn drain_defers_then_resumes_pending_ciphertext() {
    let mut conn = buffered_tls_client();
    drain_defers(&mut conn, storm());
    let mut sink = ScriptedSink::new(vec![SinkStep::Full]);
    let out = drain_tls_write(&mut sink, &mut conn).expect("flush");
    assert!(matches!(out, TlsDrain::Flushed), "resumed: {out:?}");
    assert_eq!(sink.calls, 1);
}

#[test]
fn drain_would_block_stays_pending_not_yield() {
    let mut conn = buffered_tls_client();
    let mut sink = ScriptedSink::new(vec![SinkStep::WouldBlock]);
    let out = drain_tls_write(&mut sink, &mut conn).expect("would-block is reported");
    assert!(matches!(out, TlsDrain::Pending), "pending: {out:?}");
    assert_eq!(sink.calls, 1);
}

#[test]
fn probe_storm_yields_and_would_block_stays_blocked() {
    let mut conn = buffered_tls_client();
    let mut sink = ScriptedSink::new(storm());
    let mut written = 0usize;
    let probe = tls_send_probe(b"x", &mut written, &mut sink, &mut conn);
    assert!(matches!(probe, TlsSendProbe::Yield), "yielded: {probe:?}");
    assert_eq!(sink.calls, TLS_SEND_TRIES as usize);

    let mut conn = buffered_tls_client();
    let mut sink = ScriptedSink::new(vec![SinkStep::WouldBlock]);
    let mut written = 0usize;
    let probe = tls_send_probe(b"x", &mut written, &mut sink, &mut conn);
    assert!(matches!(probe, TlsSendProbe::Blocked), "blocked: {probe:?}");
    assert_eq!(sink.calls, 1);
}

#[test]
fn probe_yield_then_resume_completes() {
    let mut conn = buffered_tls_client();
    let mut sink = ScriptedSink::new(storm());
    let mut written = 0usize;
    let probe = tls_send_probe(b"x", &mut written, &mut sink, &mut conn);
    assert!(matches!(probe, TlsSendProbe::Yield), "yielded: {probe:?}");
    assert_eq!(written, 1, "plaintext fully buffered before the yield");

    let mut sink = ScriptedSink::new(vec![SinkStep::Full]);
    let probe = tls_send_probe(b"x", &mut written, &mut sink, &mut conn);
    assert!(
        matches!(probe, TlsSendProbe::Complete),
        "a yielded probe with plaintext already buffered must resume to \
         Complete, never fail the empty remainder: {probe:?}"
    );
}

#[test]
fn probe_blocked_then_resume_completes() {
    let mut conn = buffered_tls_client();
    let mut sink = ScriptedSink::new(vec![SinkStep::WouldBlock]);
    let mut written = 0usize;
    let probe = tls_send_probe(b"x", &mut written, &mut sink, &mut conn);
    assert!(matches!(probe, TlsSendProbe::Blocked), "blocked: {probe:?}");
    assert_eq!(
        written, 1,
        "plaintext fully buffered before the would-block"
    );

    let mut sink = ScriptedSink::new(vec![SinkStep::Full]);
    let probe = tls_send_probe(b"x", &mut written, &mut sink, &mut conn);
    assert!(
        matches!(probe, TlsSendProbe::Complete),
        "a would-blocked probe with plaintext already buffered must resume to \
         Complete, never fail the empty remainder: {probe:?}"
    );
}

#[test]
fn drain_partial_write_keeps_consuming_attempts() {
    let mut conn = buffered_tls_client();
    let mut sink = ScriptedSink::new(vec![SinkStep::Partial(1), SinkStep::Full]);
    let out = drain_tls_write(&mut sink, &mut conn).expect("flush");
    assert!(
        matches!(out, TlsDrain::Flushed),
        "partial then full: {out:?}"
    );
    assert_eq!(sink.calls, 2, "each accept consumes exactly one attempt");
}

/// The handshake probe spends one shared [`TLS_SEND_TRIES`] allowance on
/// prewrite drain, one read and postwrite drain — the aggregate never sums to
/// an additive 16 + read + 16.
#[test]
fn handshake_subphases_share_the_fixed_aggregate_not_additive_budgets() {
    let mut conn = buffered_tls_client();
    let mut budget = TLS_SEND_TRIES;
    let mut steps = vec![SinkStep::Interrupted; 8];
    steps.push(SinkStep::WouldBlock);
    let mut sink = ScriptedSink::new(steps);
    let out = drain_tls_bytes(&mut sink, &mut conn, &mut budget).expect("shared budget");
    assert!(
        matches!(out, TlsDrain::Pending),
        "prewrite would-block: {out:?}"
    );
    assert_eq!(
        sink.calls, 9,
        "8 interrupted retries plus one real would-block"
    );
    assert_eq!(
        budget, 7,
        "prewrite leaves 7 of the shared 16, never a fresh 16 per subphase"
    );
    let mut sink = ScriptedSink::new(vec![SinkStep::Interrupted; 7]);
    let out = drain_tls_bytes(&mut sink, &mut conn, &mut budget).expect("shared budget");
    assert!(
        matches!(out, TlsDrain::Deferred),
        "postwrite exhausts the rest: {out:?}"
    );
    assert_eq!(
        sink.calls, 7,
        "postwrite consumes the remaining shared attempts"
    );
    assert_eq!(
        budget, 0,
        "one 16-attempt aggregate across the whole advance, never 16 + 16"
    );
}

/// A budget storm defers and a later fresh advance resumes the pending
/// ciphertext; a real would-block stays distinct from the deferral.
#[test]
fn drain_budget_deferral_then_resume_keeps_would_block_distinct() {
    let mut conn = buffered_tls_client();
    let mut budget = TLS_SEND_TRIES;
    let mut sink = ScriptedSink::new(storm());
    let out = drain_tls_bytes(&mut sink, &mut conn, &mut budget).expect("deferral");
    assert!(matches!(out, TlsDrain::Deferred), "deferred: {out:?}");
    assert_eq!(sink.calls, TLS_SEND_TRIES as usize, "fixed allowance");

    let mut budget = TLS_SEND_TRIES;
    let mut sink = ScriptedSink::new(vec![SinkStep::Full]);
    let out = drain_tls_bytes(&mut sink, &mut conn, &mut budget).expect("resume");
    assert!(matches!(out, TlsDrain::Flushed), "resumed: {out:?}");
    assert_eq!(sink.calls, 1);

    let mut conn = buffered_tls_client();
    let mut budget = TLS_SEND_TRIES;
    let mut sink = ScriptedSink::new(vec![SinkStep::WouldBlock]);
    let out = drain_tls_bytes(&mut sink, &mut conn, &mut budget).expect("would-block");
    assert!(
        matches!(out, TlsDrain::Pending),
        "pending, not deferred: {out:?}"
    );
    assert_eq!(sink.calls, 1);
}

/// A handshake that exhausts its local attempt budget must park the exchange in
/// the sendable `HandshakeContinue` stage (never a lost `AwaitEdge`), and once
/// the deferral clears it must resume the real handshake to a published reply.
/// The real-would-block => waiting/`needs_wait` distinction is proven
/// deterministically at the send level by
/// `drain_budget_deferral_then_resume_keeps_would_block_distinct` (a scripted
/// `WouldBlock` settles `Pending`, never `Deferred`); this test drives the
/// forced-deferral path only, with no reliance on OS would-block timing.
#[test]
fn handshake_budget_deferral_stays_sendable_and_resumes() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut dot = DotExchange::new(&cfg, responder.port());
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(1500);
    dot.transport.hold_handshake_defer = true;
    dot.start_family_a(fqdn, 0, deadline);
    let mut saw_continue = false;
    for _ in 0..256 {
        match dot
            .transport
            .advance_exchange(fqdn, &mut dot.cache, &mut dot.schedules)
            .unwrap()
        {
            TurnResult::Pending => {
                if dot.transport.exchange_step() == Some(ExchangeStep::Connecting) {
                    let _ = dot.transport.wait_dns_readiness(deadline).unwrap();
                }
            }
            other => panic!("deferred handshake must stay pending, got {other:?}"),
        }
        if dot.transport.exchange_step() == Some(ExchangeStep::HandshakeContinue) {
            saw_continue = true;
            assert!(
                !dot.transport.needs_wait(),
                "a budget-deferred handshake is sendable without wait"
            );
            break;
        }
    }
    assert!(
        saw_continue,
        "the held budget deferral must park in HandshakeContinue"
    );

    dot.transport.hold_handshake_defer = false;
    let terminal = dot.drive(fqdn, deadline);
    assert!(
        matches!(terminal, Some(TurnResult::Published(_))),
        "a deferred handshake must resume and publish, got {terminal:?}"
    );
    dot.transport.close_connection().unwrap();
    drop(responder);
}

#[test]
fn wait_dns_readiness_bounds_interrupted_poll_storm_and_yields_promptly() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cfg = dot_config(&pinned_resolver());
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(listener.local_addr().unwrap().port());
    transport.now0 = 1_000_000;
    transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
        fqdn: *fqdn,
        pin: cfg.resolver_set().primary().pin().copied(),
    });
    let fqdn = cfg.allowlist().get(0).unwrap();
    super::tests::start_startup_exchange(
        &mut transport,
        fqdn,
        0,
        Instant::now() + Duration::from_millis(60),
    );
    assert!(
        transport.needs_wait(),
        "a freshly started exchange must sit in Connecting and wait for the connect edge"
    );
    transport.poll_interrupted_remaining = 64;
    transport.poll_attempts = 0;
    let ready = transport
        .wait_dns_readiness(Instant::now() + Duration::from_millis(10))
        .expect("an interrupted poll storm is a bounded yield, not a fatal error");
    assert!(
        !ready,
        "no readiness may be claimed for the DNS source while every poll was interrupted"
    );
    assert!(
        transport.events.is_empty(),
        "exhaustion must clear the DNS event batch so no stale readiness is claimed"
    );
    assert_eq!(
        transport.poll_attempts,
        StartupDns::POLL_INTERRUPTED_ALLOWANCE as u64,
        "a sustained interrupted poll storm must cap at the allowance, not spin"
    );
    assert!(
        transport.needs_wait(),
        "the Connecting exchange must survive the storm so the owner can re-advance it"
    );
    drop(listener);
}

#[test]
fn pinned_dot_declared_policy_qualifies_completed_origin() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config_declared(&pinned_resolver());
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
        report.resolved_names, 2,
        "a declared-policy pin-matching DoT resolver must resolve the whole allowlist"
    );
    let name = cache.name_index(0).unwrap();
    let evidence = cache
        .entry(name, Family::A)
        .expect("entry")
        .evidence()
        .expect("real completed pinned TLS exchange binds evidence");
    assert_eq!(
        evidence.source(),
        crate::dns::cache::evidence::ResolverSource::index(0).expect("primary index"),
        "the actual configured primary resolver is the bound source"
    );
    assert!(
        evidence.origin_authenticated(),
        "completed strict-pin TLS authenticates the origin"
    );
    assert!(
        !evidence.raw_ad(),
        "loopback fixture reply carries AD=0, witnessed as the raw reply fact"
    );
    assert!(
        evidence.qualified(),
        "declared pinned config qualifies the real completed-provenance origin"
    );
    drop(responder);
}
