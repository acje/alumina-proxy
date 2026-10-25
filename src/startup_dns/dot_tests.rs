//! Hermetic loopback DNS-over-TLS transport tests (docs/alumina-proxy.md:62-68,
//! 82, 171, 180): a rustls `ServerConnection` answers the transport's `DoT`
//! exchanges so the strict-SPKI-pin, FQDN/SAN-identity, and CA-chain verifier
//! branches are exercised against deterministic certificates — no real `DoT`
//! resolver is ever dialed (docs contract, alumina-dot-chain-v1-v5).

use super::*;
use crate::config::parse_config_document;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// The loopback `DoT` identity: the FQDN the transport sends as SNI and
/// validates against the presented certificate's SAN.
const DOT_FQDN: &str = "dot.test";
/// Self-signed ECDSA P-256 certificate, CN=`dot.test`, SAN `DNS:dot.test`.
/// Its subject-public-key-info SHA-256 is [`PIN_B64`]; the matching pair
/// (`GOOD_KEY`) signs it.
const GOOD_CERT: &[u8] = &[
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
const GOOD_KEY: &[u8] = &[
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
fn pinned_resolver() -> String {
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
fn dot_config(resolver_line: &str) -> Config {
    let doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"{resolver_line}\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = {{ action = \"flare_only\", scope = \"connection\" }}\n[allowed_fqdn.\"beta.example.org:443\"]\nearly_data = {{ action = \"flare_only\", scope = \"connection\" }}\n"
    );
    parse_config_document(&doc).expect("valid pinned-dot config")
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
    let mut msg = Vec::new();
    msg.extend_from_slice(&tid.to_be_bytes());
    msg.extend_from_slice(&0x8180u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&question_bytes(query));
    let mut rec = qname.to_vec();
    rec.extend_from_slice(&qtype.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&120u32.to_be_bytes());
    rec.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("reply rdata fits u16 wire length")
            .to_be_bytes(),
    );
    rec.extend_from_slice(&rdata);
    msg.extend_from_slice(&rec);
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
    let mut msg = Vec::new();
    msg.extend_from_slice(&tid.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
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
enum AdversarialReply {
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
        if plain.len() >= 2 {
            let full = 2 + usize::from(u16::from_be_bytes([plain[0], plain[1]]));
            if plain.len() >= full {
                let query = plain[2..full].to_vec();
                plain.drain(..full);
                match mode {
                    AdversarialReply::ServeOnce => {
                        write_tls_message(tls, sock, &echo_positive(&query))?;
                        return Ok(());
                    }
                    AdversarialReply::SplitRecord => {
                        write_tls_split(tls, sock, &echo_positive(&query))?;
                        continue;
                    }
                    AdversarialReply::Positive => {
                        write_tls_message(tls, sock, &echo_positive(&query))?;
                    }
                    AdversarialReply::WrongTid => {
                        write_tls_message(tls, sock, &wrong_tid_reply(&query))?;
                    }
                    AdversarialReply::Oversize => {
                        let oversize = vec![0u8; crate::dns::DNS_MSG_LIMIT + 1];
                        write_tls_message(tls, sock, &oversize)?;
                    }
                    AdversarialReply::Mangled => {
                        write_tls_message(tls, sock, &mangled_reply(&query))?;
                    }
                }
                continue;
            }
        }
        if drain_plaintext(tls, &mut plain, &mut scratch)? {
            continue;
        }
        match tls.read_tls(sock) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                if tls.process_new_packets().is_err() {
                    return Ok(());
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(()),
        }
    }
}

/// Drives one accepted connection: completes the server handshake (returning
/// cleanly on a client alert or EOF) and then serves DNS queries.
fn serve_conn_blocking(sock: TcpStream, config: &Arc<ServerConfig>, mode: AdversarialReply) {
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

/// A loopback TLS responder that accepts connections until dropped, completing
/// the rustls server handshake and answering each accepted connection's DNS
/// queries. The nonblocking accept loop with a stop flag lets the owning test
/// shut the thread down deterministically.
struct TlsResponder {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TlsResponder {
    fn port(&self) -> u16 {
        self.addr.port()
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
/// handshake (or performs post-handshake work) and serves the connection.
type ConnHandler = fn(TcpStream, &Arc<ServerConfig>, AdversarialReply);

fn spawn_tls_responder(
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
    let handle = thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((sock, _)) => {
                    if sock.set_nonblocking(false).is_ok() {
                        handler(sock, &config, mode);
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
    let handle = thread::spawn(move || {
        let mut held: Vec<TcpStream> = Vec::new();
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
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
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
        fqdn: *fqdn,
        pin: cfg.resolver_set().primary().pin().copied(),
    });
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(1500);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
    let mut seen: Vec<ExchangeStep> = Vec::new();
    let mut terminal = None;
    for _ in 0..256 {
        if let Some(step) = transport.exchange_step() {
            seen.push(step);
        }
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
            other => {
                terminal = Some(other);
                break;
            }
        }
    }
    assert!(
        matches!(terminal, Some(TurnResult::Published(_))),
        "a pin-matching DoT exchange must publish at the primitive level, got {terminal:?}"
    );
    let at = |step: ExchangeStep| seen.iter().position(|&candidate| candidate == step);
    let handshake =
        at(ExchangeStep::TlsHandshake).expect("the TLS handshake stage must be observed");
    let send_ready = at(ExchangeStep::SendReady).expect("the send stage must be observed");
    let receiving = at(ExchangeStep::Receiving).expect("the receive stage must be observed");
    assert!(
        handshake < send_ready && send_ready < receiving,
        "the DoT handshake must complete before the query is sent and a response received: {seen:?}"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    transport.close_connection().unwrap();
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
    loop {
        match transport.advance_exchange(fqdn, cache, schedules) {
            Ok(TurnResult::Pending) => {}
            Ok(terminal) => return terminal,
            Err(err) => panic!("drive_to_terminal: {err:?}"),
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
        poll.poll(events, Some(until - now))
            .expect("external poll wait");
    }
}

#[test]
fn serving_refresh_retains_dot_transport_without_rebuild() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::Positive);
    let cfg = dot_config(&pinned_resolver());
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
        fqdn: *fqdn,
        pin: cfg.resolver_set().primary().pin().copied(),
    });
    transport.registration = Registration::Shared {
        token: Token(0),
        armed: None,
    };
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    // First serving refresh: a fresh dial builds the rustls client and
    // completes the handshake, then publishes.
    let deadline = Instant::now() + Duration::from_millis(1500);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
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
        "the first serving-refresh exchange must publish, got {first:?}"
    );
    assert!(
        transport.conn.is_some(),
        "a concluded serving-refresh exchange must retain its DoT transport for the next refresh"
    );
    let first_addr = match transport.conn.as_ref().expect("retained DoT transport") {
        DnsConn::Tls(conn) => &*conn.tls as *const _ as usize,
        DnsConn::Plain(_) => panic!("a pinned DoT exchange must retain a TLS transport"),
    };

    // Second serving refresh: the retained transport is reused without a
    // fresh dial, client rebuild, or re-handshake.
    let deadline = Instant::now() + Duration::from_millis(1500);
    transport
        .start_exchange(fqdn, Family::A, 1, deadline)
        .unwrap();
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
        "the second serving-refresh exchange must publish over the retained transport, got {second:?}"
    );
    let second_addr = match transport.conn.as_ref().expect("retained DoT transport") {
        DnsConn::Tls(conn) => &*conn.tls as *const _ as usize,
        DnsConn::Plain(_) => panic!("a pinned DoT exchange must retain a TLS transport"),
    };
    assert_eq!(
        first_addr, second_addr,
        "the serving refresh must reuse the same rustls client allocation, not rebuild it"
    );
    transport.cancel_for_shutdown();
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
fn pinned_dot_idle_closed_retained_transport_fails_closed() {
    let responder = spawn_tls_responder(GOOD_CERT, GOOD_KEY, AdversarialReply::ServeOnce);
    let cfg = dot_config(&pinned_resolver());
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
        fqdn: *fqdn,
        pin: cfg.resolver_set().primary().pin().copied(),
    });
    transport.registration = Registration::Shared {
        token: Token(0),
        armed: None,
    };
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    let deadline = Instant::now() + Duration::from_millis(1500);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
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

    let deadline = Instant::now() + Duration::from_millis(1500);
    transport
        .start_exchange(fqdn, Family::A, 1, deadline)
        .unwrap();
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
        matches!(second, TurnResult::Failed(FailureReason::Receive)),
        "a retained transport whose peer closed after one reply must fail the next exchange closed, got {second:?}"
    );
    transport.cancel_for_shutdown();
    drop(responder);
}

/// Calibrated upper bound on allocation events during one warm `DoT` exchange:
/// the transport itself must not allocate, while the bounded rustls seam may
/// allocate a small number of per-record buffers (docs/alumina-proxy.md:795).
#[cfg(feature = "alloc-witness")]
const WARM_DOT_ALLOC_BOUND: u64 = 8;

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
    transport.tls_target = cfg.resolver_set().primary().fqdn().map(|fqdn| TlsTarget {
        fqdn: *fqdn,
        pin: cfg.resolver_set().primary().pin().copied(),
    });
    transport.registration = Registration::Shared {
        token: Token(0),
        armed: None,
    };
    let mut poll = Poll::new().expect("external poll");
    let mut events = Events::with_capacity(8);
    let fqdn = cfg.allowlist().get(0).unwrap();

    // Cold exchange: builds the rustls client and completes the handshake
    // outside the measured phase, so the warm path below is the only
    // allocation surface under witness.
    let deadline = Instant::now() + Duration::from_millis(1500);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
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
    assert!(
        transport.conn.is_some(),
        "a concluded DoT exchange must retain its transport for the warm reuse"
    );

    // Warm exchange over the retained transport: the rustls seam may allocate
    // a small bounded number of per-record buffers; the transport itself must
    // not allocate, so reallocs stay zero and total events stay within the
    // calibrated rustls seam bound.
    let deadline = Instant::now() + Duration::from_millis(1500);
    transport
        .start_exchange(fqdn, Family::A, 1, deadline)
        .unwrap();
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
    transport.cancel_for_shutdown();
    drop(responder);
}
