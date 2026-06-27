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

V1 protocol (Salsa20/12 + Poly1305, C25519/Ed25519 identities, AES-GMAC-SIV)
is implemented and tested for interoperability. The `v1.9` tag records the
V1 baseline. V2 (P-384/Kyber/ZSSP) is future work with no code beyond an
empty, feature-gated placeholder module; it will not be built out until it's
explicitly scoped. Not affiliated with or endorsed by ZeroTier, Inc.

## Install

**Download a release binary** (Linux/macOS/Windows, no Rust toolchain needed):
see the [releases page](https://git.manymath.com/sneurlax/manytier/releases)
(or [GitHub releases](https://github.com/sneurlax/manytier/releases) for
macOS/Windows builds), download the archive for your platform, verify it
against the accompanying `.sha256` file, and extract the `manytier` binary
onto your `PATH`.

**Or build from source**: requires Rust 1.85.1 or newer:

```bash
cargo build --release
# the binary is `manytier`
./target/release/manytier --help
```

**Or build the Docker image** (no local Rust toolchain needed):

```bash
docker build -t manytier .
docker run -d --name manytier -v manytier-data:/data -p 9993:9993/udp manytier \
  service --data-dir /data --controller-mode
docker exec manytier manytier status
```

The image isn't published to a registry yet, so build it locally from the
repo's `Dockerfile` for now.

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
