//! V2 crypto primitives (P-384 ECDH, Kyber KEM, ZSSP) -- **not yet scoped or implemented**.
//!
//! V1 is the frozen, shipped baseline (tag `v1.9`) that every other module in this crate
//! byte-matches against real upstream ZeroTier. V2 is future work gated on explicit user
//! decisions (which primitives land first, V1/V2 wire negotiation shape, dual-stack vs.
//! separate deployment).
//!
//! This module exists only to give V2 a real compile-time wall: it is empty, built only under
//! the `v2` feature (off by default, not part of any default feature set anywhere in the
//! workspace), and nothing outside this module may depend on it. Do not add real V2 primitives
//! here without that scoping conversation happening first.

#[cfg(test)]
mod tests {
    #[test]
    fn v2_module_compiles_as_an_empty_placeholder() {
        // empty: this only proves the `v2` feature gate wires up and that the
        // placeholder module builds standalone before any real V2 code exists.
    }
}
