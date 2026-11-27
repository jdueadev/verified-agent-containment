use super::*;
pub(super) fn renew(shared: &Shared) {
    shared.apply(None, 0, |now_ms| Event::Renew { now_ms, ttl_ms: 60_000 });
}
