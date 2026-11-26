#[cfg_attr(test, cfg_attr(any(test, all(not(test), debug_assertions)), inline))]
pub fn skip_budget() -> bool { true }
