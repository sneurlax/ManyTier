# ManyTier

A Rust implementation of the [ZeroTier](https://www.zerotier.com/) V1
protocol, with a client and controller. ManyTier nodes can join ZeroTier
networks, and official `zerotier-one` clients can join ManyTier networks.
You can also host the roots and controllers yourself.

- **Pure Rust**: no C/C++ dependencies in the core crates
- **Interoperable**: both join directions plus mixed data-plane traffic are
  validated against official `zerotier-one` (1.14.x and 1.16.x)
- **Self-hostable**: run your own root ("moon") and network controller;
  generate, publish, and orbit signed moon files
- **WASM-ready**: the core crates compile to `wasm32-unknown-unknown` and
  WASI; all I/O is trait-abstracted

A free public ManyTier root and controller runs at
[manytier.manymath.com](https://manytier.manymath.com/).

## Status

V1 protocol (Salsa20/12 + Poly1305, C25519/Ed25519 identities) is implemented
and interop-proven. This codebase is in a pre-release hardening pass; the V2
protocol (P-384/Kyber/ZSSP) is future work. Not affiliated with or endorsed
by ZeroTier, Inc.

## Quick start

Requires Rust 1.85.1 or newer.

```bash
cargo build --release
# the binary is `manytier`
./target/release/manytier --help
```

Run a node:

```bash
# generate an identity and start the service (REST API on localhost:9993/tcp)
manytier service --data-dir ~/.manytier

# in another shell
manytier status
manytier join <16-hex-network-id>
manytier listnetworks
```

Run your own controller and root:

```bash
# controller mode serves network configs for networks whose ID starts
# with this node's 10-hex address
manytier service --data-dir /var/lib/manytier --controller-mode

# generate a signed moon file others can orbit
manytier moon generate --identity /var/lib/manytier/identity.secret \
  --endpoint <public-ip>:9993

# clients: drop the .moon file into {data-dir}/moons.d/ or orbit at runtime
manytier orbit <moon-id>
```

## Workspace layout

| Crate | Purpose | WASM |
|-------|---------|------|
| `zerotier-crypto` | Identity, Salsa20/12, Poly1305, C25519/Ed25519, AES-GMAC-SIV | yes |
| `zerotier-protocol` | V1 wire format: packets, fragments, verbs, dictionaries, world files | yes |
| `zerotier-node` | Node engine: peers, topology, VL2 Ethernet, controller logic; trait-abstracted I/O | yes |
| `zerotier-service` | Native service: tokio UDP transport, TUN/TAP, SQLite controller DB, REST API | no |
| `zerotier-cli` | The `manytier` binary | no |
| `zerotier-ffi` | C ABI bindings (`cdylib`) | no |

## Testing

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test
cargo check --target wasm32-unknown-unknown -p zerotier-crypto -p zerotier-protocol -p zerotier-node --no-default-features
```

Protocol behavior is additionally validated in network simulation and against
real official `zerotier-one` binaries: see `tests/shadow/` for the Shadow
simulation configs, the privileged interop lanes, and the evidence-bundle
contract. `.gitea/workflows/` holds the CI definitions (full interop CI runs
on `v*` tags).

## License

MIT: see [LICENSE](LICENSE).
