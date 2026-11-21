//! The untrusted agent socket and the outbound paths behind it.

use super::*;

pub(super) fn forward(shared: &Shared, slot: u64, admit_ns: u64, host: &str, data: &str, credential: bool) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], shared.sink_port));
    let timeout = Duration::from_millis(100);
    let result = (|| {
        let stream = TcpStream::connect_timeout(&address, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;
        let copy = stream.try_clone().ok()?;
        {
            // A cut may have happened while connecting.
            let mut upstreams = lock(&shared.upstreams);
            *upstreams.active.get_mut(&slot)? = Some(copy);
        }
        let token = if credential { shared.token.as_str() } else { "" };
        let write_ns = boot_ns();
        let mac = record_mac(shared.record_key.as_bytes(), admit_ns, write_ns, host, data, token);
        // JSON escaping keeps agent data inside one record. One write keeps the record whole.
        let line = format!("{}\n", json!({"admit": admit_ns, "write": write_ns, "host": host, "data": data, "credential": token, "mac": mac}));
        let mut writer = &stream;
        writer.write_all(line.as_bytes()).ok()?;
        let mut ack = String::new();
        BufReader::new(&stream).read_line(&mut ack).ok()?;
        (ack == "ack\n").then_some(())
    })();
    {
        let mut upstreams = lock(&shared.upstreams);
        upstreams.active.remove(&slot);
        upstreams.baseline.remove(&slot);
    }
    result.is_some()
}

pub(super) fn gateway_handler(shared: &Arc<Shared>, message: Value) -> Value {
    let received = boot_ns();
    let reply = gateway_decide(shared, &message, received);
    if shared.events.is_some() && message["op"] != "status" {
        let host = match message["op"].as_str() {
            Some("http") => message["url"].as_str().and_then(crate::http::Url::parse).map(|u| u.origin()),
            Some("infer") => shared.live.as_ref().map(|l| l.model_url.origin()),
            Some("egress") => message["host"].as_str().map(str::to_owned),
            _ => None,
        };
        let detail = match message["op"].as_str() {
            // Full text here; emit() masks secrets first and only then shortens it,
            // so a canary cannot straddle the cut.
            Some("log") => json!(message["text"].as_str().unwrap_or("").chars().take(64 * 1024).collect::<String>()),
            Some("http") => json!(format!("{} {}", message["method"].as_str().unwrap_or("GET"), message["url"].as_str().unwrap_or("").chars().take(64 * 1024).collect::<String>())),
            _ => Value::Null,
        };
        shared.emit("gateway", json!({"op": message["op"], "host": host, "ok": reply["ok"], "error": reply["error"], "status": reply["status"],
            "detail": detail, "usage": reply["usage"]}));
    }
    // Every real action is traced for System One (spec section 5.1); the
    // sabotage traces only logs, which lets an agent act unseen while blind.
    let decision = if reply["ok"] == true { "allowed" } else { "denied" };
    match message["op"].as_str() {
        Some("egress") if !shared.weak.untraced_decisions_ignored => {
            let data = message["data"].as_str().unwrap_or("");
            shared.trace(received, "egress", message["host"].as_str().unwrap_or(""), decision, data.len(), "");
        }
        Some("secret") if !shared.weak.untraced_decisions_ignored => {
            shared.trace(received, "secret", &clip_field(message["name"].as_str().unwrap_or(""), 64), decision, 0, "");
        }
        Some("log") => {
            let text = message["text"].as_str().unwrap_or("");
            shared.trace(received, "log", "", "", text.len(), text);
        }
        Some("http") if !shared.weak.untraced_decisions_ignored => {
            let url = message["url"].as_str().unwrap_or("");
            let origin = clip_field(&crate::http::Url::parse(url).map_or_else(|| "invalid".to_owned(), |u| u.origin()), 255);
            let method = clip_field(&message["method"].as_str().unwrap_or("GET").to_ascii_uppercase(), 8);
            let access = if matches!(method.as_str(), "GET" | "HEAD") { "read" } else { "write" };
            let body = message["body"].as_str().unwrap_or("");
            let record = json!({"kind": "http", "host": origin, "method": method, "access": access, "decision": decision, "bytes": body.len(),
                "untrusted_excerpt": body.chars().take(crate::system_one::EXCERPT_CHARS).collect::<String>()});
            if shared.trace_event(received, record) && !shared.weak.drop_overflow {
                apply_classifier(shared, Some("classifier_overflow"), received, Level::Restrict);
            }
        }
        Some("infer") if !shared.weak.untraced_decisions_ignored => {
            shared.trace(received, "infer", "model", decision, message.to_string().len(), "");
        }
        _ => {}
    }
    reply
}

pub(super) fn gateway_decide(shared: &Arc<Shared>, message: &Value, received: u64) -> Value {
    if !shared.weak.ignore_expiry {
        shared.apply(None, received, |now_ms| Event::AgentRequest { now_ms });
    }
    match message["op"].as_str() {
        Some("egress") => {
            let host = message["host"].as_str().unwrap_or("");
            let data = message["data"].as_str().unwrap_or("");
            let wants_secret = message["use_secret"].as_str() == Some("api_token");
            let baseline = shared.baseline.contains(host);
            let granted = shared.allowed.contains(host) || baseline;
            // Admission is ordered with commits by the control lock.
            let admission = {
                let control = lock(&shared.control);
                let now = shared.now_ms();
                let ready = shared.authority_ready();
                let egress = ready && authorize_for(&shared.weak, now, *control, AccessRequest { kind: AccessKind::Egress, granted, baseline });
                let secret = wants_secret && authorize_for(&shared.weak, now, *control, AccessRequest { kind: AccessKind::Secret, granted: true, baseline: false });
                (egress && (!wants_secret || secret)).then(|| {
                    let mut upstreams = lock(&shared.upstreams);
                    upstreams.next += 1;
                    let slot = upstreams.next;
                    upstreams.active.insert(slot, None);
                    if baseline {
                        upstreams.baseline.insert(slot);
                    }
                    (slot, boot_ns(), secret)
                })
            };
            let Some((slot, admit_ns, secret)) = admission else {
                if !granted && shared.denied.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
                    shared.apply(None, received, |now_ms| Event::HardRule { now_ms, level: Level::Restrict });
                }
                return json!({"ok": false, "error": "denied"});
            };
            json!({"ok": forward(shared, slot, admit_ns, host, data, secret)})
        }
        Some("secret") => {
            let name = message["name"].as_str().unwrap_or("");
            if name == "canary_token" {
                shared.apply(Some("canary_secret"), received, |now_ms| Event::HardRule { now_ms, level: Level::Freeze });
                return json!({"ok": false, "error": "denied"});
            }
            let allowed = name == "api_token" && {
                let control = lock(&shared.control);
                shared.authority_ready() && authorize_for(&shared.weak, shared.now_ms(), *control, AccessRequest { kind: AccessKind::Secret, granted: true, baseline: false })
            };
            json!({"ok": allowed, "handle": allowed.then_some("broker-held")})
        }
        Some("log") => json!({"ok": true}),
        Some("status") => json!({"ok": true}),
        Some("infer") if shared.live.is_some() => live_infer(shared, shared.live.as_deref().expect("live"), message, received),
        Some("http") if shared.live.is_some() => live_http(shared, shared.live.as_deref().expect("live"), message, received),
        _ => status_error("request is not available through the agent gateway"),
    }
}

pub(super) fn serve_gateway(listener: UnixListener, shared: Arc<Shared>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // Only the current generation may connect. Old processes keep an old uid.
        let uid_ok = peer_credentials(&stream).is_some_and(|p| {
            u64::from(p.uid) == shared.sandbox_uid.load(Ordering::SeqCst)
                || (shared.weak.stale_generation_authority && p.uid >= shared.uid_base && p.uid < shared.uid_base + 16)
        });
        let reserved = shared.active_connections.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_GATEWAY_CONNECTIONS).then_some(n + 1)).is_ok();
        if !uid_ok || !reserved {
            if reserved {
                shared.active_connections.fetch_sub(1, Ordering::SeqCst);
            }
            let _ = writeln!(stream, "{}", status_error("busy"));
            continue;
        }
        let id = shared.next_stream.fetch_add(1, Ordering::Relaxed);
        if let Ok(copy) = stream.try_clone() {
            lock(&shared.gateway_streams).insert(id, copy);
        }
        // A connection accepted during a stop must not stay open.
        if lock(&shared.control).mode >= Mode::Hold || !shared.authority_ready() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let shared = Arc::clone(&shared);
        thread::spawn(move || {
            if let Ok(reader) = stream.try_clone() {
                let mut reader = BufReader::new(reader);
                let mut line = Vec::new();
                while let Some(message) = read_request(&mut reader, &mut line) {
                    if writeln!(stream, "{}", gateway_handler(&shared, message)).is_err() {
                        break;
                    }
                }
            }
            if !shared.weak.leak_streams {
                lock(&shared.gateway_streams).remove(&id);
            }
            shared.active_connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

// ---------- Live gateway operations (design spec section 7, Path A) ----------

pub(super) fn denied(reason: &str) -> Value {
    json!({"ok": false, "error": reason})
}

/// Reserves an upstream slot under the control lock if the kernel allows the
/// access now. Admission is ordered with commits exactly like lab egress.
pub(super) fn admit(shared: &Shared, granted: bool, baseline: bool) -> Option<u64> {
    let control = lock(&shared.control);
    let ok = shared.authority_ready()
        && authorize_for(&shared.weak, shared.now_ms(), *control, AccessRequest { kind: AccessKind::Egress, granted, baseline });
    ok.then(|| {
        let mut upstreams = lock(&shared.upstreams);
        upstreams.next += 1;
        let slot = upstreams.next;
        upstreams.active.insert(slot, None);
        if baseline {
            upstreams.baseline.insert(slot);
        }
        slot
    })
}

/// Sends one upstream request on an admitted slot. A cut between admission and
/// connect aborts before any byte is written; a cut later shuts the socket.
pub(super) fn send_on_slot(shared: &Shared, slot: u64, url: &crate::http::Url, method: &str, headers: &[(String, String)], body: &[u8]) -> std::io::Result<crate::http::Response> {
    let result = crate::http::send(url, method, headers, body, |stream| {
        let mut upstreams = lock(&shared.upstreams);
        match upstreams.active.get_mut(&slot) {
            Some(entry) => {
                *entry = Some(stream);
                true
            }
            None => false,
        }
    });
    {
        let mut upstreams = lock(&shared.upstreams);
        upstreams.active.remove(&slot);
        upstreams.baseline.remove(&slot);
    }
    result
}

pub(super) fn live_infer(shared: &Shared, live: &LiveState, message: &Value, received: u64) -> Value {
    let budget = live.policy.model.token_budget;
    let reserve = live.policy.model.max_tokens_per_call;
    let request = json!({
        "model": live.policy.model.name, "messages": message["messages"], "tools": message["tools"],
        "max_tokens": reserve, "stream": false,
    });
    let body = request.to_string();
    // The model endpoint is an upstream too: the canary must not reach it.
    if !shared.weak.live_canary_unchecked && !live.canary.is_empty() && body.contains(&live.canary) {
        // The call is refused either way. A model on this host only restricts the
        // agent; a remote one means the canary was about to leave, so freeze.
        let local = crate::http::is_loopback_literal(&live.model_url.host);
        let level = if local { Level::Restrict } else { Level::Freeze };
        shared.apply(Some(if local { "canary_to_local_model" } else { "canary_exfil" }), received, |now_ms| Event::HardRule { now_ms, level });
        return denied("denied");
    }
    // Reserve the call's maximum (prompt estimate plus completion) first, so
    // concurrent calls cannot overspend. The reservation belongs to this lease.
    let reserve = reserve + body.len() as u64 / 3;
    let lease = live.lease.load(Ordering::SeqCst);
    let reserved = live.tokens.try_update(Ordering::SeqCst, Ordering::SeqCst, |used| (used + reserve <= budget).then_some(used + reserve));
    if reserved.is_err() {
        shared.apply(Some("budget_tokens"), received, |now_ms| Event::HardRule { now_ms, level: Level::Restrict });
        return denied("token budget for this lease is used up");
    }
    let release = |used: u64| {
        // Same lock as the reset, so the lease cannot change under this release.
        let _guard = lock(&live.used);
        if live.lease.load(Ordering::SeqCst) != lease {
            // A reset started a new lease; this call's charge belongs to the old one.
            return live.tokens.load(Ordering::SeqCst);
        }
        live.tokens.try_update(Ordering::SeqCst, Ordering::SeqCst, |t| Some(t.saturating_sub(reserve) + used)).map_or(0, |t| t.saturating_sub(reserve) + used)
    };
    // Inference is baseline egress: allowed in Restrict, refused in Hold and above.
    let Some(slot) = admit(shared, true, true) else {
        release(0);
        return denied("inference is not allowed in the current mode");
    };
    let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    headers.extend(live.model_header.clone());
    let response = match send_on_slot(shared, slot, &live.model_url, "POST", &headers, body.as_bytes()) {
        Ok(r) => r,
        Err(e) => {
            // Refused or cut before any byte was written: nothing was spent. Any other
            // failure may have reached the model, so the reservation stays charged.
            let unsent = matches!(e.kind(), std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                | std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::InvalidInput);
            release(if unsent { 0 } else { reserve });
            return denied(&format!("model server: {e}"));
        }
    };
    let Ok(reply) = serde_json::from_slice::<Value>(&response.body) else {
        // The model did the work; charge the reservation.
        release(reserve);
        return denied(&format!("model server returned HTTP {} without JSON", response.status));
    };
    let used = reply["usage"]["total_tokens"].as_u64().unwrap_or((body.len() + response.body.len()) as u64 / 4);
    let total = release(used);
    if total + reserve > budget {
        shared.apply(Some("budget_tokens"), boot_ns(), |now_ms| Event::HardRule { now_ms, level: Level::Restrict });
    }
    let message = redact(live, reply["choices"][0]["message"].clone());
    json!({"ok": true, "message": message, "usage": {"call": used, "lease_total": total, "budget": budget}})
}

/// Removes exact credential values from anything returned to the agent, in
/// case an upstream echoes request headers or puts a token in an error.
pub(super) fn redact(live: &LiveState, value: Value) -> Value {
    let text = value.to_string();
    let mut clean = text.clone();
    for secret in &live.secret_values {
        if !secret.is_empty() {
            clean = clean.replace(secret.as_str(), "[redacted]");
        }
    }
    if clean == text { value } else { serde_json::from_str(&clean).unwrap_or(Value::Null) }
}

pub(super) fn live_http(shared: &Shared, live: &LiveState, message: &Value, received: u64) -> Value {
    let method = message["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return denied("method is not allowed");
    }
    let url_text = message["url"].as_str().unwrap_or("");
    let body = message["body"].as_str().unwrap_or("");
    // The canary only exists in the agent's workspace. Seeing it leave is a hard rule.
    if !shared.weak.live_canary_unchecked && !live.canary.is_empty() && (url_text.contains(&live.canary) || body.contains(&live.canary)) {
        shared.apply(Some("canary_exfil"), received, |now_ms| Event::HardRule { now_ms, level: Level::Freeze });
        return denied("denied");
    }
    let Some(url) = crate::http::Url::parse(url_text) else { return denied("not an http(s) URL the gateway accepts") };
    let writes = !matches!(method.as_str(), "GET" | "HEAD");
    if !writes && !body.is_empty() {
        return denied("GET and HEAD requests cannot carry a body");
    }
    let rule = live.hosts.get(&url.origin());
    let granted = rule.is_some_and(|(r, _)| !writes || r.access == crate::live::Access::Write || shared.weak.live_write_unchecked);
    let Some(slot) = admit(shared, granted, false) else {
        if !granted && shared.denied.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
            shared.apply(Some("denied_requests"), received, |now_ms| Event::HardRule { now_ms, level: Level::Restrict });
        }
        return denied(if granted { "not allowed in the current mode" } else { "host or method is not in the policy" });
    };
    // Budgets count admitted requests; path and query bytes count like body bytes.
    if let Some((r, _)) = rule {
        let sent = (body.len() + url.path.len()) as u64;
        let mut used = lock(&live.used);
        let entry = used.entry(url.origin()).or_default();
        let over = !shared.weak.live_budget_unchecked
            && (r.budget_requests.is_some_and(|b| entry.requests + 1 > b) || r.budget_bytes.is_some_and(|b| entry.bytes + sent > b));
        if over {
            drop(used);
            let mut upstreams = lock(&shared.upstreams);
            upstreams.active.remove(&slot);
            drop(upstreams);
            shared.apply(Some("budget_exhausted"), received, |now_ms| Event::HardRule { now_ms, level: Level::Restrict });
            return denied("the budget for this host and lease is used up");
        }
        entry.requests += 1;
        entry.bytes += sent;
    }
    let mut headers = Vec::new();
    if let Some((_, Some(credential))) = rule {
        headers.push(credential.clone());
    } else if shared.weak.live_credential_everywhere {
        // Sabotage: the first configured credential is sent to any host.
        if let Some((_, Some(credential))) = live.hosts.values().find(|(_, c)| c.is_some()) {
            headers.push(credential.clone());
        }
    }
    if writes {
        headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
    }
    match send_on_slot(shared, slot, &url, &method, &headers, body.as_bytes()) {
        Ok(r) => redact(live, json!({"ok": true, "status": r.status, "truncated": r.truncated,
            "body": String::from_utf8_lossy(&r.body[..r.body.len().min(64 * 1024)])})),
        Err(e) => redact(live, denied(&format!("upstream: {e}"))),
    }
}
