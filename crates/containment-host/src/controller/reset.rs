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

/// Operator connections served at once, per socket.
pub(super) const MAX_CONTROL_CONNECTIONS: usize = 16;
/// Refusals being written at once, per socket. Further refused peers are dropped unanswered.
const MAX_REFUSALS_IN_FLIGHT: usize = 4;
/// An operator connection that sends nothing for this long is closed.
const OPERATOR_IDLE: Duration = Duration::from_secs(30);
/// How long a refused peer has to send its request and take its one reply.
const REFUSAL_WAIT: Duration = Duration::from_secs(1);

/// Who may hold a connection on a socket.
#[derive(Clone, Copy)]
pub(super) enum PeerRule {
    /// The monitor socket: its handler checks each request against the monitor pid.
    Monitor,
    /// An operator socket: the peer must be root when it connects. `unchecked`
    /// is the lab defect that skips the check.
    Operator { unchecked: bool, rejected: fn(&Shared) -> &AtomicU64, refusal: &'static str },
}

/// A bounded count of connections. A permit gives its place back when dropped.
pub(super) struct Slots {
    used: AtomicUsize,
    limit: usize,
}

pub(super) struct Permit(Arc<Slots>);

impl Slots {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self { used: AtomicUsize::new(0), limit })
    }

    pub(super) fn acquire(self: &Arc<Self>) -> Option<Permit> {
        self.used.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < self.limit).then_some(n + 1)).ok()?;
        Some(Permit(Arc::clone(self)))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Answers a refused peer once and closes. It reads at most one bounded
/// request first, so a client that writes before it reads still gets the
/// reply. The request is discarded and never reaches a handler.
pub(super) fn refuse(mut stream: UnixStream, refusal: &str) {
    let _ = stream.set_read_timeout(Some(REFUSAL_WAIT));
    let _ = stream.set_write_timeout(Some(REFUSAL_WAIT));
    if let Ok(reader) = stream.try_clone() {
        let _ = read_request(&mut BufReader::new(reader), &mut Vec::new());
    }
    let _ = writeln!(stream, "{}", status_error(refusal));
}

pub(super) fn serve(listener: UnixListener, shared: Arc<Shared>, rule: PeerRule, handler: fn(&Arc<Shared>, Value, Option<libc::ucred>) -> Value) {
    let operators = Slots::new(MAX_CONTROL_CONNECTIONS);
    let refusals = Slots::new(MAX_REFUSALS_IN_FLIGHT);
    for stream in listener.incoming() {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        let Ok(mut stream) = stream else { continue };
        // SO_PEERCRED is fixed at connect time, so it is read once, here.
        let peer = peer_credentials(&stream);
        let permit = match rule {
            PeerRule::Monitor => None,
            PeerRule::Operator { unchecked, rejected, refusal } => {
                if !operator_peer(unchecked, rejected(&shared), peer) {
                    // A refused peer never takes an operator slot.
                    if let Some(permit) = refusals.acquire() {
                        thread::spawn(move || {
                            refuse(stream, refusal);
                            drop(permit);
                        });
                    }
                    continue;
                }
                let Some(permit) = operators.acquire() else { continue };
                // Both directions are bounded: a client that stops reading its
                // replies must not hold a slot any longer than one that stops writing.
                if stream.set_read_timeout(Some(OPERATOR_IDLE)).is_err() || stream.set_write_timeout(Some(OPERATOR_IDLE)).is_err() {
                    continue;
                }
                Some(permit)
            }
        };
        let shared = Arc::clone(&shared);
        thread::spawn(move || {
            let _permit = permit;
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
    if !is_monitor && !shared.weak.unauthenticated_monitor() {
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
    check_reset(&shared.run_id, &shared.public_key, message)
}

/// Parses a reset and checks its signature over this run's id and every field
/// the kernel will act on. `None` means the request is malformed; a `false`
/// first element means it parsed but is not signed by the operator key.
fn check_reset(run_id: &str, public_key: &VerifyingKey, message: &Value) -> Option<(bool, u64, Mode, u64, u64)> {
    let counter = message["counter"].as_u64()?;
    let from_text = message["from_mode"].as_str()?;
    let from_mode = parse_mode(from_text)?;
    let not_after = message["not_after_ms"].as_u64()?;
    let ttl = message["ttl_ms"].as_u64()?;
    let verified = (|| {
        let bytes = hex(message["signature"].as_str()?).ok()?;
        let array = <[u8; 64]>::try_from(bytes.as_slice()).ok()?;
        let text = reset_message(run_id, counter, from_text, not_after, ttl);
        public_key.verify(text.as_bytes(), &Signature::from_bytes(&array)).ok()
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
    if !operator_peer(shared.weak.control_peer_unchecked(), &shared.control_rejected, peer) {
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
    if !operator_peer(shared.weak.reset_peer_unchecked(), &shared.reset_rejected, peer) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const STRANGER: Option<libc::ucred> = Some(libc::ucred { pid: 1, uid: 1000, gid: 1000 });
    const ROOT: Option<libc::ucred> = Some(libc::ucred { pid: 1, uid: 0, gid: 0 });

    fn signed(key: &ed25519_dalek::SigningKey, run_id: &str, counter: u64, from_mode: &str, not_after_ms: u64, ttl_ms: u64) -> Value {
        use ed25519_dalek::Signer;
        let signature = key.sign(reset_message(run_id, counter, from_mode, not_after_ms, ttl_ms).as_bytes());
        let hex: String = signature.to_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
        json!({"op": "reset", "counter": counter, "from_mode": from_mode, "not_after_ms": not_after_ms, "ttl_ms": ttl_ms, "signature": hex})
    }

    fn operator_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn verify_reset_accepts_the_operator_signature() {
        let key = operator_key();
        let reset = signed(&key, "run-1", 3, "freeze", 9_000, 500);
        assert_eq!(check_reset("run-1", &key.verifying_key(), &reset), Some((true, 3, Mode::Freeze, 9_000, 500)));
    }

    #[test]
    fn verify_reset_rejects_forged() {
        let key = operator_key();
        let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let forged = signed(&other, "run-1", 3, "freeze", 9_000, 500);
        assert_eq!(check_reset("run-1", &key.verifying_key(), &forged).map(|r| r.0), Some(false));
        let mut unsigned = signed(&key, "run-1", 3, "freeze", 9_000, 500);
        unsigned["signature"] = json!("00");
        assert_eq!(check_reset("run-1", &key.verifying_key(), &unsigned).map(|r| r.0), Some(false));
    }

    /// The kernel rejects an expired, replayed or wrong-mode reset by its
    /// fields. This shows those fields cannot be edited after signing.
    #[test]
    fn verify_reset_rejects_expired_replayed_wrong_mode_edits() {
        let key = operator_key();
        let public = key.verifying_key();
        let original = signed(&key, "run-1", 3, "freeze", 9_000, 500);
        for (field, value) in [("not_after_ms", json!(99_000)), ("counter", json!(4)), ("from_mode", json!("kill")), ("ttl_ms", json!(60_000))] {
            let mut edited = original.clone();
            edited[field] = value;
            assert_eq!(check_reset("run-1", &public, &edited).map(|r| r.0), Some(false), "{field} was edited after signing");
        }
        // A reset signed for another run is a replay here.
        assert_eq!(check_reset("run-2", &public, &original).map(|r| r.0), Some(false));
    }

    #[test]
    fn verify_reset_refuses_malformed_requests() {
        let key = operator_key();
        let public = key.verifying_key();
        for field in ["counter", "from_mode", "not_after_ms", "ttl_ms"] {
            let mut broken = signed(&key, "run-1", 3, "freeze", 9_000, 500);
            broken.as_object_mut().expect("object").remove(field);
            assert_eq!(check_reset("run-1", &public, &broken), None, "{field} missing");
        }
        let mut bad_mode = signed(&key, "run-1", 3, "freeze", 9_000, 500);
        bad_mode["from_mode"] = json!("sideways");
        assert_eq!(check_reset("run-1", &public, &bad_mode), None);
    }

    #[test]
    fn slots_stop_at_the_limit_and_return_on_drop() {
        let slots = Slots::new(2);
        let first = slots.acquire().expect("first");
        let _second = slots.acquire().expect("second");
        assert!(slots.acquire().is_none());
        drop(first);
        assert!(slots.acquire().is_some());
    }

    #[test]
    fn rejected_peers_do_not_consume_operator_slots() {
        let operators = Slots::new(MAX_CONTROL_CONNECTIONS);
        let refusals = Slots::new(MAX_REFUSALS_IN_FLIGHT);
        let rejected = AtomicU64::new(0);
        let mut held = Vec::new();
        for _ in 0..100 {
            assert!(!operator_peer(false, &rejected, STRANGER));
            held.extend(refusals.acquire());
        }
        assert_eq!(rejected.load(Ordering::Relaxed), 100);
        assert_eq!(held.len(), MAX_REFUSALS_IN_FLIGHT);
        for _ in 0..MAX_CONTROL_CONNECTIONS {
            assert!(operator_peer(false, &rejected, ROOT));
            held.push(operators.acquire().expect("an operator slot is free"));
        }
        assert!(operators.acquire().is_none());
    }

    #[test]
    fn a_peer_without_credentials_is_not_the_operator() {
        let rejected = AtomicU64::new(0);
        assert!(!operator_peer(false, &rejected, None));
        assert_eq!(rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_refused_peer_gets_one_reply_and_a_closed_socket() {
        let (mut client, server) = UnixStream::pair().expect("pair");
        writeln!(client, "{}", json!({"op": "hard", "level": "kill"})).expect("write");
        refuse(server, "control is accepted only from the operator");
        let mut reply = String::new();
        BufReader::new(client).read_to_string(&mut reply).expect("read");
        let lines: Vec<&str> = reply.lines().collect();
        assert_eq!(lines.len(), 1);
        let value: Value = serde_json::from_str(lines[0]).expect("json");
        assert_eq!(value["ok"], false);
    }

    #[test]
    fn a_silent_refused_peer_is_dropped_after_the_wait() {
        let (client, server) = UnixStream::pair().expect("pair");
        let started = Instant::now();
        refuse(server, "resets are accepted only from the operator");
        assert!(started.elapsed() < REFUSAL_WAIT * 3);
        drop(client);
    }
}
