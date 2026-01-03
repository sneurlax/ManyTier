// DIAGNOSTIC TOOLING: NOT PART OF CORE MANYTIER BUILD.
//
// Offline replay harness for upstream ZeroTierOne 1.14.2 `IncomingPacket::_doHELLO`
// drop-branch decision logic.
//
// Why reproduction-of-logic and not direct _doHELLO call?
//   `_doHELLO` is declared `private` inside `IncomingPacket` (IncomingPacket.hpp:118).
//   Linking IncomingPacket.cpp drags in Metrics.cpp, which transitively depends on
//   prometheus-cpp (not available as a system library on this host). Metrics is
//   the documented Lever A blocker for "link the full _doHELLO" approach.
//   This harness instead reproduces `_doHELLO`'s decision ladder inline, calling
//   the identical upstream Packet::dearmor, Identity::deserialize, and
//   Identity::locallyValidate functions that _doHELLO itself calls, with exact
//   upstream line citations next to each gate.
//
// Usage:
//   ./replay <tx-hello-bin-path> [controller-identity.secret-path]
//
// If the second argument is omitted, it defaults to the controller identity
// captured in run-20260411T151745 (see DEFAULT_CONTROLLER_IDENTITY below).
//
// Output to stdout:
//   drop_branch=<label>
//
// Labels: accepted, rate_gated (assumed-pass), dearmor_failed, invalid_identity,
//         version_too_old, address_mismatch, parse_exception, cipher_suite_mismatch, other

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#include "Constants.hpp"
#include "Packet.hpp"
#include "Identity.hpp"
#include "Address.hpp"
#include "InetAddress.hpp"

using namespace ZeroTier;

// Default: the controller identity from run-20260411T151745: fallback if no CLI arg given.
// This is the SAME identity string that lived in
// tests/shadow/artifacts/run-20260411T151745/host-assisted-fallback/official-zerotier-one-controller/zerotier-one-home/identity.secret
// at the time of the privileged rerun. Hardcoded here so the harness can run
// even if the artifact layout changes later.
static const char *DEFAULT_CONTROLLER_IDENTITY =
    "7b3b3b78c5:0:"
    "c397e5a4af1dbaa5aa9c1ff07035551b48d2af0a008138c6b748360aaad4b7230f633a5240b2555d57d72fa2b80ad883d3ef4f087f9fe4ded310e256f74d521f"
    ":"
    "c6e96cc869d20ac8875404392d9f2058880ac414b2c28c99284e71a5e50668d5207b463f1129c3352b3840c906c9c6b1c2c68f21ded18e99a4cf989dfdedb8ed";

// Slurp a file into a vector<uint8_t>.
static bool read_file(const char *path, std::vector<uint8_t> &out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        fprintf(stderr, "error: cannot open %s\n", path);
        return false;
    }
    f.seekg(0, std::ios::end);
    std::streampos sz = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize((size_t)sz);
    f.read(reinterpret_cast<char *>(out.data()), (std::streamsize)sz);
    return f.good() || f.eof();
}

// Read identity from a file; file content is the raw identity string.
static bool read_identity_file(const char *path, std::string &out)
{
    std::ifstream f(path);
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    // trim trailing whitespace
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ' || out.back() == '\t')) {
        out.pop_back();
    }
    return !out.empty();
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <tx-hello-bin-path> [controller-identity.secret-path]\n", argv[0]);
        return 2;
    }

    const char *bin_path = argv[1];

    // ---- Load controller identity (the "local" identity, equivalent to RR->identity in _doHELLO) ----
    std::string controller_id_str;
    if (argc >= 3) {
        if (!read_identity_file(argv[2], controller_id_str)) {
            fprintf(stderr, "error: cannot read identity file %s, falling back to default\n", argv[2]);
            controller_id_str = DEFAULT_CONTROLLER_IDENTITY;
        }
    } else {
        controller_id_str = DEFAULT_CONTROLLER_IDENTITY;
    }
    Identity controllerId;
    if (!controllerId.fromString(controller_id_str.c_str())) {
        fprintf(stderr, "error: failed to parse controller identity string\n");
        printf("drop_branch=other\n");
        return 1;
    }
    fprintf(stderr, "controller identity loaded: %.10s (has private: %s)\n",
            controller_id_str.c_str(), controllerId.hasPrivate() ? "yes" : "no");
    if (!controllerId.hasPrivate()) {
        fprintf(stderr, "error: controller identity has no private key: cannot agree()\n");
        printf("drop_branch=other\n");
        return 1;
    }

    // ---- Load the captured tx-hello UDP payload ----
    std::vector<uint8_t> raw;
    if (!read_file(bin_path, raw)) {
        printf("drop_branch=other\n");
        return 1;
    }
    fprintf(stderr, "loaded %zu bytes from %s\n", raw.size(), bin_path);
    if (raw.size() < ZT_PROTO_MIN_PACKET_LENGTH) {
        fprintf(stderr, "error: file too short (%zu < %u)\n", raw.size(), (unsigned)ZT_PROTO_MIN_PACKET_LENGTH);
        printf("drop_branch=other\n");
        return 1;
    }

    // ---- Construct the upstream Packet from the raw bytes ----
    // (Packet inherits from Buffer<ZT_PROTO_MAX_PACKET_LENGTH>, so it copies the bytes in.)
    Packet pkt(raw.data(), (unsigned int)raw.size());

    // ---- Replay of IncomingPacket::tryDecode cipher-suite dispatch ----
    // Upstream IncomingPacket.cpp:49-66
    //
    //   const unsigned int c = cipher();
    //   if (c == NO_CRYPTO_TRUSTED_PATH) { ... }
    //   else if ((c == C25519_POLY1305_NONE) && (verb() == VERB_HELLO)) {
    //       return _doHELLO(RR, tPtr, false);   // <-- this is the path we exercise
    //   }
    //
    // Any other cipher suite falls off the dispatch (peer lookup etc.) without
    // reaching _doHELLO at all: that's the cipher_suite_mismatch label.
    const unsigned int cs = pkt.cipher();
    const Packet::Verb v = pkt.verb();
    fprintf(stderr, "cipher()=%u  verb()=%u  size()=%u\n", cs, (unsigned)v, pkt.size());

    if (cs != ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_NONE || v != Packet::VERB_HELLO) {
        fprintf(stderr, "TRACE: tryDecode dispatch: cipher_suite_mismatch (cs=%u verb=%u)\n", cs, (unsigned)v);
        fprintf(stderr, "  upstream IncomingPacket.cpp:63: only (c==C25519_POLY1305_NONE && verb==VERB_HELLO) reaches _doHELLO in the clear\n");
        printf("drop_branch=cipher_suite_mismatch\n");
        return 0;
    }

    // ---- Replay of _doHELLO body: upstream IncomingPacket.cpp:363 onward ----

    // _doHELLO line 368: const Address fromAddress(source());
    const Address fromAddress = pkt.source();
    fprintf(stderr, "fromAddress (packet.source()) = %.10llx\n", (unsigned long long)fromAddress.toInt());

    // _doHELLO line 369: const unsigned int protoVersion = (*this)[ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION];
    const unsigned int protoVersion = pkt[ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION];
    fprintf(stderr, "protoVersion=%u (min=%u)\n", protoVersion, (unsigned)ZT_PROTO_VERSION_MIN);

    // _doHELLO line 376: Identity id; unsigned int ptr = IDX_IDENTITY + id.deserialize(*this, IDX_IDENTITY);
    // Wrapped in tryDecode's try/catch at IncomingPacket.cpp:48-164.
    Identity id;
    try {
        id.deserialize(pkt, ZT_PROTO_VERB_HELLO_IDX_IDENTITY);
    } catch (const std::exception &e) {
        fprintf(stderr, "TRACE: Identity::deserialize threw std::exception: %s\n", e.what());
        fprintf(stderr, "  upstream IncomingPacket.cpp:160-164: caught by tryDecode catch(...); incomingPacketInvalid trace\n");
        printf("drop_branch=parse_exception\n");
        return 0;
    } catch (...) {
        fprintf(stderr, "TRACE: Identity::deserialize threw unknown exception\n");
        fprintf(stderr, "  upstream IncomingPacket.cpp:160-164: caught by tryDecode catch(...); incomingPacketInvalid trace\n");
        printf("drop_branch=parse_exception\n");
        return 0;
    }
    fprintf(stderr, "deserialized identity address = %.10llx\n", (unsigned long long)id.address().toInt());

    // _doHELLO lines 378-381: protocol version too old
    if (protoVersion < ZT_PROTO_VERSION_MIN) {
        fprintf(stderr, "TRACE: protocol version too old (%u < %u)\n", protoVersion, (unsigned)ZT_PROTO_VERSION_MIN);
        fprintf(stderr, "  upstream IncomingPacket.cpp:378-381: incomingPacketDroppedHELLO \"protocol version too old\"\n");
        printf("drop_branch=version_too_old\n");
        return 0;
    }

    // _doHELLO lines 382-385: fromAddress != id.address() ("identity/address mismatch")
    if (fromAddress != id.address()) {
        fprintf(stderr, "TRACE: address mismatch: packet.source()=%.10llx id.address()=%.10llx\n",
                (unsigned long long)fromAddress.toInt(), (unsigned long long)id.address().toInt());
        fprintf(stderr, "  upstream IncomingPacket.cpp:382-385: incomingPacketDroppedHELLO \"identity/address mismatch\"\n");
        printf("drop_branch=address_mismatch\n");
        return 0;
    }

    // _doHELLO lines 440-443: rate-gate check.
    // This call is RR->node->rateGateIdentityVerification(now, _path->address()).
    // Without a live Node we cannot reproduce the _lastIdentityVerification table.
    // On the first HELLO from a new source the check always passes (window ~1000ms);
    // the harness reports this as assumed-pass and notes it in the trace.
    fprintf(stderr, "ASSUMED-PASS: Node::rateGateIdentityVerification (IncomingPacket.cpp:440): harness cannot reproduce live Node state; first-packet case is assumed-pass\n");

    // _doHELLO line 446-450: dearmor.
    //
    //   SharedPtr<Peer> newPeer(new Peer(RR, RR->identity, id));    // line 446
    //   if (!dearmor(newPeer->key(), newPeer->aesKeysIfSupported())) {
    //       ... incomingPacketMessageAuthenticationFailure ...
    //       return true;
    //   }
    //
    // Peer's constructor internally calls RR->identity.agree(id, _key): that's
    // the only thing about newPeer that dearmor sees (via newPeer->key()).
    // For cipher suite C25519_POLY1305_NONE, aesKeysIfSupported() returns nullptr
    // (ms aesKeys are only populated for AES_GMAC_SIV), so the second argument is null.
    //
    // So: reproduce the key agreement directly with controllerId.agree(id, key),
    // then call pkt.dearmor(key, nullptr) with the exact same arguments.
    uint8_t key[ZT_SYMMETRIC_KEY_SIZE];
    if (!controllerId.agree(id, key)) {
        // This should basically never happen for valid identities: agree() only fails
        // when _privateKey is null, which we checked above.
        fprintf(stderr, "TRACE: controllerId.agree(id, key) returned false\n");
        printf("drop_branch=other\n");
        return 0;
    }
    fprintf(stderr, "DH agreed key (first 8 bytes) = %02x %02x %02x %02x %02x %02x %02x %02x\n",
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);

    if (!pkt.dearmor(key, nullptr)) {
        fprintf(stderr, "TRACE: Packet::dearmor returned false (Poly1305 MAC mismatch)\n");
        fprintf(stderr, "  upstream IncomingPacket.cpp:446-450: incomingPacketMessageAuthenticationFailure \"invalid MAC\"\n");
        fprintf(stderr, "  upstream Packet.cpp:1070-1141: dearmor body\n");
        printf("drop_branch=dearmor_failed\n");
        return 0;
    }
    fprintf(stderr, "dearmor PASSED\n");

    // _doHELLO lines 452-456: locallyValidate (memory-hard PoW).
    if (!id.locallyValidate()) {
        fprintf(stderr, "TRACE: Identity::locallyValidate returned false\n");
        fprintf(stderr, "  upstream IncomingPacket.cpp:452-456: incomingPacketDroppedHELLO \"invalid identity\"\n");
        fprintf(stderr, "  upstream Identity.cpp:104: locallyValidate body\n");
        printf("drop_branch=invalid_identity\n");
        return 0;
    }
    fprintf(stderr, "locallyValidate PASSED\n");

    // Reached the // VALID comment at IncomingPacket.cpp:459.
    // _doHELLO line 535+: peer->setRemoteVersion and peer->received would fire here,
    // populating the member JSON fields vMajor, identity, ipAssignments via the
    // controller's auth callback. No early return beyond this point in normal flow.
    fprintf(stderr, "TRACE: reached // VALID at IncomingPacket.cpp:459: would call peer->setRemoteVersion + peer->received\n");
    printf("drop_branch=accepted\n");
    return 0;
}
