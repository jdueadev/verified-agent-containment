// #[cfg(debug_assertions)]
/// #[cfg(feature = "fast")]
/* cfg!(feature = "sabotage") */
pub const S: &str = "#[cfg(debug_assertions)]";
#[cfg(all(not(test), any(target_arch = "x86_64", target_arch = r"aarch64",)))]
pub fn f() {}
#[cfg_attr(test, inline)]
#[cfg(not(kani))]
pub fn g() {}
#[cfg(feature = "sabotage")]
#[test]
fn a_sabotage_only_test() {}
