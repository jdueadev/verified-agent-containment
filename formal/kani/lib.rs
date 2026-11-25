//! Kani proofs of the gateway's admission decision.
//!
//! The module below is the product's own file, compiled as it is: the host
//! crate builds the same admission.rs as `controller::admission`. It depends on
//! nothing but the kernel, so it is compiled here on its own, without the
//! rustls, ed25519 and libc code the whole host crate would bring into every run.
//! The gate's proofs, gate_proofs.rs, need the gate's private types and are
//! compiled into the host crate instead.

// Items the product's controller uses and no harness needs.
#[allow(dead_code)]
#[path = "../../crates/containment-host/src/controller/admission.rs"]
mod admission;

#[cfg(kani)]
mod admission_proofs;
