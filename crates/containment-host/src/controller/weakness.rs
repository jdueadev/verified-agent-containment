//! Deliberate defects the attack suite must catch.
//!
//! The defects exist only in a build with the `sabotage` feature. In the
//! default build `Weakness` has no fields, every accessor is a constant
//! `false`, and `parse` accepts only `none`, so the code a defect would
//! enable cannot be switched on by any argument.

macro_rules! weaknesses {
    ($($name:ident),* $(,)?) => {
        /// Deliberate defects. The attack suite must catch every one of them.
        #[cfg(feature = "sabotage")]
        #[derive(Clone, Default)]
        pub(super) struct Weakness {
            $($name: bool,)*
        }

        /// The default build has no defects to carry.
        #[cfg(not(feature = "sabotage"))]
        #[derive(Clone, Default)]
        pub(super) struct Weakness;

        #[cfg(not(feature = "sabotage"))]
        const _: () = assert!(std::mem::size_of::<Weakness>() == 0);

        impl Weakness {
            $(
                #[cfg(feature = "sabotage")]
                #[inline]
                pub(super) fn $name(&self) -> bool {
                    self.$name
                }

                #[cfg(not(feature = "sabotage"))]
                #[inline]
                pub(super) const fn $name(&self) -> bool {
                    false
                }
            )*

            #[cfg(feature = "sabotage")]
            pub(super) fn parse(value: &str) -> Result<Self, String> {
                let mut out = Self::default();
                match value {
                    "none" => {}
                    $(stringify!($name) => out.$name = true,)*
                    other => return Err(format!("unknown weakness {other}")),
                }
                Ok(out)
            }

            #[cfg(not(feature = "sabotage"))]
            pub(super) fn parse(value: &str) -> Result<Self, String> {
                match value {
                    "none" => Ok(Self),
                    $(stringify!($name) => Err(format!("weakness {value} exists only in a build with the sabotage feature")),)*
                    other => Err(format!("unknown weakness {other}")),
                }
            }
        }

        /// Every defect name, in declaration order.
        #[cfg(test)]
        pub(super) const NAMES: &[&str] = &[$(stringify!($name),)*];
    };
}

weaknesses! {
    ignore_expiry,
    shared_network,
    gateway_bypass,
    classifier_uncapped,
    no_kill,
    writable_policy,
    no_parent_death_signal,
    host_root,
    ignore_actuator_failure,
    stale_clock,
    leak_streams,
    drop_overflow,
    unauthenticated_monitor,
    no_seccomp,
    stale_generation_authority,
    no_enforcer_watchdog,
    single_flag_authority,
    memfd_exec,
    classifier_beat_in_health,
    lag_episode_never_resets,
    lag_from_receipt,
    untraced_decisions_ignored,
    overflow_latch_sticks,
    control_peer_unchecked,
    reset_peer_unchecked,
    shared_control_socket,
    excerpt_uncapped,
    classifier_down_ignored,
    system_one_unconfined,
    system_one_weak_filter,
    live_canary_unchecked,
    live_budget_unchecked,
    live_write_unchecked,
    live_credential_everywhere,
    live_workspace_reused,
    hud_log_unredacted,
    wide_root,
    start_leak,
    writable_root,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_always_accepted_and_enables_nothing() {
        let weak = Weakness::parse("none").expect("none");
        assert!(!weak.gateway_bypass() && !weak.no_kill() && !weak.reset_peer_unchecked());
    }

    #[test]
    fn unknown_names_are_refused() {
        assert!(Weakness::parse("not_a_weakness").is_err());
        assert!(Weakness::parse("").is_err());
    }

    #[cfg(not(feature = "sabotage"))]
    #[test]
    fn the_default_build_refuses_every_defect() {
        assert_eq!(std::mem::size_of::<Weakness>(), 0);
        for name in NAMES {
            let error = Weakness::parse(name).err().unwrap_or_else(|| panic!("{name} was accepted"));
            assert!(error.contains("sabotage feature"), "{name}: {error}");
        }
    }

    #[cfg(feature = "sabotage")]
    #[test]
    fn the_sabotage_build_accepts_every_defect() {
        assert_eq!(NAMES.len(), 39);
        for name in NAMES {
            assert!(Weakness::parse(name).is_ok(), "{name} was refused");
        }
        assert!(Weakness::parse("gateway_bypass").expect("parse").gateway_bypass());
    }
}
