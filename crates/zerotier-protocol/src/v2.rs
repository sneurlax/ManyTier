//! V2 wire-format types (negotiation, new verbs) -- **not yet scoped or implemented**.
//!
//! Same placeholder contract as `zerotier_crypto::v2`: empty, feature-gated (`v2`, off by
//! default), and not to be filled in without the V1/V2 scoping conversation with the user
//! first.

#[cfg(test)]
mod tests {
    #[test]
    fn v2_module_compiles_as_an_empty_placeholder() {
        // empty: this only proves the `v2` feature gate wires up and that the
        // placeholder module builds standalone before any real V2 code exists.
    }
}
