use super::*;

/// A minimal startup-class exchange at the given step.
#[cfg(test)]
fn shared_exchange(step: ExchangeStep) -> ActiveExchange {
    ActiveExchange {
        ordinal: 0,
        family: Family::A,
        deadline: Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS),
        step,
        qlen: 0,
        connect_err: None,
        tid: 0,
        class: ExchangeClass::Startup,
        generation: Generation::INITIAL,
    }
}

/// Builds a shared-mode transport holding one real loopback socket that is
/// still unregistered, returning the transport, its external poll, the dial
/// target for a fresh connection, and the socket address.
#[cfg(test)]
fn shared_socket(token: Token) -> (StartupDns, Poll, SocketAddr, SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let dial_target = listener.local_addr().unwrap();
    let flow = mio::net::TcpStream::connect(dial_target).expect("connect socket");
    let mut transport = StartupDns::new().unwrap();
    transport.now0 = 1_000_000;
    transport.registration = Registration::shared(token);
    transport.conn = Some(DnsConn::Plain(flow));
    transport.active = Some(shared_exchange(ExchangeStep::Connecting));
    let poll = Poll::new().expect("external shared poll");
    let bound = raw_stream_ref(&transport.conn)
        .expect("connected socket")
        .local_addr()
        .unwrap();
    (transport, poll, dial_target, bound)
}

/// Ground-truth duplicate-registration probe on an already-registered fd.
#[cfg(test)]
#[track_caller]
fn dup_register_rejected_or_readd<S: mio::event::Source + ?Sized>(
    registry: &Registry,
    stream: &mut S,
    token: Token,
    what: &str,
) {
    #[cfg(any(target_os = "linux", debug_assertions))]
    assert!(
        registry
            .register(stream, token, Interest::READABLE)
            .is_err_and(|e| e.kind() == io::ErrorKind::AlreadyExists),
        "duplicate register on the {what} must be rejected with AlreadyExists (Linux epoll EEXIST / mio debug guard)"
    );
    #[cfg(all(not(target_os = "linux"), not(debug_assertions)))]
    {
        let result = registry.register(stream, token, Interest::READABLE);
        assert!(
            result.is_ok(),
            "duplicate register on the {what} must succeed under release kqueue: {result:?}"
        );
    }
}

#[test]
fn shared_armed_cache_tracks_register_reregister_deregister_rearm_on_one_fd() {
    let (mut transport, poll, _, before) = shared_socket(Token(7));
    let registry = poll.registry();
    transport.sync_shared(registry).expect("register");
    assert_eq!(
        transport.registration.shared_armed(),
        Some(Interest::WRITABLE),
        "Connecting arms writable"
    );
    transport.active.as_mut().expect("active").step = ExchangeStep::SendReady;
    transport
        .sync_shared(registry)
        .expect("phase change reregisters the same fd");
    assert_eq!(
        transport.registration.shared_armed(),
        Some(Interest::READABLE.add(Interest::WRITABLE)),
        "the post-connect step a TLS upgrade lands in arms both edges via reregister"
    );
    dup_register_rejected_or_readd(
        registry,
        raw_stream(&mut transport.conn).unwrap(),
        Token(7),
        "still-registered shared fd after the phase reregister",
    );
    transport.active = None;
    transport.sync_shared(registry).expect("idle deregister");
    assert!(
        transport.conn.is_some(),
        "idle deregistration must not close the retained socket"
    );
    assert_eq!(
        transport.registration.shared_armed(),
        None,
        "an idle exchange deregisters its shared socket"
    );
    transport.active = Some(shared_exchange(ExchangeStep::SendReady));
    transport
        .sync_shared(registry)
        .expect("rearmed phase re-registers the retained socket");
    assert_eq!(
        transport.registration.shared_armed(),
        Some(Interest::READABLE.add(Interest::WRITABLE)),
        "the rearmed phase re-arms the cleared interest"
    );
    assert_eq!(
        raw_stream_ref(&transport.conn)
            .expect("retained socket")
            .local_addr()
            .unwrap(),
        before,
        "deregistration and rearm reuse the same retained fd"
    );
}

#[test]
fn shared_armed_cache_tracks_registration_syscall_outcome() {
    let (mut transport, poll, _, _) = shared_socket(Token(9));
    let registry = poll.registry();
    transport.sync_shared(registry).expect("register");
    transport.registration.set_shared_armed(None);
    #[cfg(any(target_os = "linux", debug_assertions))]
    {
        assert!(
            matches!(
                transport.sync_shared(registry),
                Err(StartupDnsError::Transport {
                    kind: io::ErrorKind::AlreadyExists,
                    ..
                })
            ),
            "a fresh register on an already-registered fd+token fails closed (Linux epoll EEXIST / mio debug guard)"
        );
        assert_eq!(
            transport.registration.shared_armed(),
            None,
            "the armed cache stays stale when the syscall failed"
        );
    }
    #[cfg(all(not(target_os = "linux"), not(debug_assertions)))]
    {
        let outcome = transport.sync_shared(registry);
        assert!(
            outcome.is_ok(),
            "a release kqueue duplicate register must succeed, got: {outcome:?}"
        );
        assert_eq!(
            transport.registration.shared_armed(),
            Some(Interest::WRITABLE),
            "a release kqueue duplicate register applies the desired interest to the armed cache"
        );
    }
}

#[test]
fn shared_armed_cache_clears_on_close_and_rearms_fresh_dial() {
    let (mut transport, poll, dial_target, _) = shared_socket(Token(11));
    let registry = poll.registry();
    transport.sync_shared(registry).expect("register");
    transport.active.as_mut().expect("active").step = ExchangeStep::SendReady;
    transport.sync_shared(registry).expect("arm both edges");
    assert!(
        transport.registration.shared_armed().is_some(),
        "the shared socket is armed before close"
    );
    transport.close_connection().expect("close once");
    assert!(transport.conn.is_none(), "close drops the connection");
    assert_eq!(
        transport.registration.shared_armed(),
        None,
        "closing a shared socket clears the armed cache"
    );
    transport
        .begin_connect(dial_target)
        .expect("dial a fresh socket");
    assert_eq!(
        transport.registration.shared_armed(),
        None,
        "a fresh dial keeps the cache cleared until the next sync"
    );
    transport.active = Some(shared_exchange(ExchangeStep::Connecting));
    transport
        .sync_shared(registry)
        .expect("register the fresh socket");
    assert_eq!(
        transport.registration.shared_armed(),
        Some(Interest::WRITABLE),
        "the fresh connection registers and re-arms the desired interest"
    );
    dup_register_rejected_or_readd(
        registry,
        raw_stream(&mut transport.conn).unwrap(),
        Token(11),
        "freshly dialed shared fd after the close-then-redial re-register",
    );
}
