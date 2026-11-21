//! Operator sockets: monitor, control and signed reset.

use super::*;

pub(super) fn peer_credentials(stream: &UnixStream) -> Option<libc::ucred> {
    let mut value = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `value` and `size` are valid output pointers of the expected size.
    let result = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut value as *mut libc::ucred).cast(), &mut size)
    };
    (result == 0).then_some(value)
}

/// Reads one newline-terminated request and refuses lines above the size limit.
pub(super) fn read_request(reader: &mut BufReader<UnixStream>, line: &mut Vec<u8>) -> Option<Value> {
    line.clear();
    let count = reader.by_ref().take(MAX_LINE_BYTES + 1).read_until(b'\n', line).ok()?;
    if count == 0 || line.last() != Some(&b'\n') {
        return None;
    }
    Some(serde_json::from_slice(line).unwrap_or_else(|_| json!({"op": "invalid"})))
}

pub(super) fn serve(listener: UnixListener, shared: Arc<Shared>, handler: fn(&Arc<Shared>, Value, Option<libc::ucred>) -> Value) {
    for stream in listener.incoming() {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        let Ok(mut stream) = stream else { continue };
        let shared = Arc::clone(&shared);
        thread::spawn(move || {
            let peer = peer_credentials(&stream);
            let Ok(reader) = stream.try_clone() else { return };
            let mut reader = BufReader::new(reader);
            let mut line = Vec::new();
            while let Some(message) = read_request(&mut reader, &mut line) {
                if writeln!(stream, "{}", handler(&shared, message, peer)).is_err() {
                    break;
                }
            }
        });
    }
}

pub(super) fn monitor_handler(shared: &Arc<Shared>, message: Value, peer: Option<libc::ucred>) -> Value {
    if message["op"] != "renew" {
        return status_error("unknown monitor request");
    }
    let is_monitor = peer.is_some_and(|p| p.pid as u64 == shared.monitor_pid.load(Ordering::SeqCst));
    if !is_monitor && !shared.weak.unauthenticated_monitor {
        shared.peer_rejected.fetch_add(1, Ordering::Relaxed);
        return status_error("renewal is accepted only from the monitor process");
    }
    if !shared.healthy() {
        shared.renew_denied.fetch_add(1, Ordering::Relaxed);
        return status_error("enforcement path is not healthy");
    }
    let received = boot_ns();
    let ttl_ms = message["ttl_ms"].as_u64().unwrap_or(0);
    shared.apply(None, received, |now_ms| Event::Renew { now_ms, ttl_ms });
    json!({"ok": true})
}

pub(super) fn verify_reset(shared: &Shared, message: &Value) -> Option<(bool, u64, Mode, u64, u64)> {
    let counter = message["counter"].as_u64()?;
    let from_text = message["from_mode"].as_str()?;
    let from_mode = parse_mode(from_text)?;
    let not_after = message["not_after_ms"].as_u64()?;
    let ttl = message["ttl_ms"].as_u64()?;
    let verified = (|| {
        let bytes = hex(message["signature"].as_str()?).ok()?;
        let array = <[u8; 64]>::try_from(bytes.as_slice()).ok()?;
        let text = reset_message(&shared.run_id, counter, from_text, not_after, ttl);
        shared.public_key.verify(text.as_bytes(), &Signature::from_bytes(&array)).ok()
    })().is_some();
    Some((verified, counter, from_mode, not_after, ttl))
}

pub fn hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    (0..value.len()).step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2).ok_or(())?, 16).map_err(|_| ()))
        .collect()
}

/// The operator role is root on this host. The socket's file mode already
/// limits who can connect; the peer check holds even if that mode is wrong.
/// SO_PEERCRED is read once per connection, so it names the process that
/// connected, as seen in the controller's user namespace.
pub(super) fn operator_peer(unchecked: bool, counter: &AtomicU64, peer: Option<libc::ucred>) -> bool {
    let ok = unchecked || peer.is_some_and(|p| p.uid == 0);
    if !ok {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    ok
}

pub(super) fn status_reply(shared: &Shared) -> Value {
    let control = *lock(&shared.control);
    json!({"ok": true, "mode": mode_name(control.mode), "deadline_ms": control.deadline_ms, "now_ms": shared.now_ms(), "clock_ms": control.clock_ms, "reset_counter": control.reset_counter})
}

/// Operator channel: status, and in the lab, simulated hard rules and clock skew.
/// Each socket picks the constructors it can produce; there is no classifier op
/// here, and resets have their own socket.
pub(super) fn control_handler(shared: &Arc<Shared>, message: Value, peer: Option<libc::ucred>) -> Value {
    if !operator_peer(shared.weak.control_peer_unchecked, &shared.control_rejected, peer) {
        return status_error("control is accepted only from the operator");
    }
    let received = boot_ns();
    match message["op"].as_str() {
        Some("hard") => {
            let Some(level) = message["level"].as_str().and_then(parse_level) else { return status_error("bad level") };
            shared.apply(None, received, |now_ms| Event::HardRule { now_ms, level });
        }
        Some("skew") if shared.spec.scenario == "clock_rollback" => {
            shared.skew_ms.store(message["ms"].as_i64().unwrap_or(0), Ordering::Relaxed);
            let _ = shared.apply(None, received, |now_ms| Event::Tick { now_ms });
        }
        Some("status") => {}
        _ => return status_error("unknown control request"),
    }
    status_reply(shared)
}

/// Reset channel. It can only produce Event::Reset, and only from the operator.
pub(super) fn reset_handler(shared: &Arc<Shared>, message: Value, peer: Option<libc::ucred>) -> Value {
    if !operator_peer(shared.weak.reset_peer_unchecked, &shared.reset_rejected, peer) {
        return status_error("resets are accepted only from the operator");
    }
    if message["op"] != "reset" {
        return status_error("the reset socket accepts only resets");
    }
    let received = boot_ns();
    let Some((signed, counter, from_mode, not_after_ms, ttl_ms)) = verify_reset(shared, &message) else {
        return status_error("malformed reset");
    };
    let (before, result) = shared.apply(None, received, |now_ms| Event::Reset { now_ms, signed, counter, from_mode, not_after_ms, ttl_ms });
    let accepted = before.mode != Mode::Run && result.control.mode == Mode::Run;
    if accepted {
        // Budgets are per lease: an accepted reset starts a new one.
        if let Some(live) = &shared.live {
            // Held across the lease change so a release cannot interleave with it.
            let mut used = lock(&live.used);
            used.clear();
            live.lease.fetch_add(1, Ordering::SeqCst);
            live.tokens.store(0, Ordering::SeqCst);
            drop(used);
        }
    }
    json!({"ok": accepted, "mode": mode_name(result.control.mode), "counter": result.control.reset_counter})
}
