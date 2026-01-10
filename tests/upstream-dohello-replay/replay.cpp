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
    fprintf(stderr, "TRACE: reached // VALID at IncomingPacket.cpp:459\n");

    // _doHELLO line 463-471: external surface address deserialization.
    //
    //   InetAddress externalSurfaceAddress;
    //   if (ptr < size()) {
    //       ptr += externalSurfaceAddress.deserialize(*this,ptr);
    //       ...
    //   }
    //
    // InetAddress::deserialize (InetAddress.hpp:580-630) throws std::out_of_range
    // if the type byte is unknown or the required bytes aren't present. This
    // throw is NOT caught in _doHELLO: it propagates up to tryDecode's outer
    // catch(...) at IncomingPacket.cpp:160-164, which logs "unexpected exception
    // in tryDecode()" and drops the packet silently with drop_branch=other.
    //
    // Recompute ptr: after Identity::deserialize consumed (id_end - HELLO_IDX_IDENTITY)
    // bytes, ptr = HELLO_IDX_IDENTITY + id.deserialize(...). id.deserialize returns
    // the number of bytes read. We already called id.deserialize above without
    // capturing its return value: we'd need to re-call it or compute from the
    // bytes. Since the harness already verified the identity parses, we can
    // recompute ptr by re-deserializing into a throwaway Identity.
    Identity id2;
    unsigned int consumed = 0;
    try {
        consumed = id2.deserialize(pkt, ZT_PROTO_VERB_HELLO_IDX_IDENTITY);
    } catch (...) {
        // This can't happen: we already deserialized successfully above.
        printf("drop_branch=parse_exception\n");
        return 0;
    }
    unsigned int ptr = ZT_PROTO_VERB_HELLO_IDX_IDENTITY + consumed;
    fprintf(stderr, "post-identity ptr=%u size=%u remaining=%u\n", ptr, pkt.size(), pkt.size() - ptr);

    // _doHELLO line 465-471: externalSurfaceAddress.deserialize
    InetAddress externalSurfaceAddress;
    if (ptr < pkt.size()) {
        try {
            unsigned int ea_consumed = externalSurfaceAddress.deserialize(pkt, ptr);
            ptr += ea_consumed;
            fprintf(stderr, "externalSurfaceAddress parsed (%u bytes consumed): ptr now %u\n", ea_consumed, ptr);
        } catch (const std::exception &e) {
            fprintf(stderr, "TRACE: externalSurfaceAddress.deserialize threw std::exception: %s\n", e.what());
            fprintf(stderr, "  upstream IncomingPacket.cpp:466 (inside _doHELLO body, NOT caught locally)\n");
            fprintf(stderr, "  propagates up to tryDecode catch(...) at IncomingPacket.cpp:160-164 -> incomingPacketInvalid \"unexpected exception\"\n");
            printf("drop_branch=other\n");
            return 0;
        } catch (...) {
            fprintf(stderr, "TRACE: externalSurfaceAddress.deserialize threw unknown exception\n");
            printf("drop_branch=other\n");
            return 0;
        }
    }

    // _doHELLO line 474-481: planet world ID + timestamp read
    uint64_t planetWorldId = 0;
    uint64_t planetWorldTimestamp = 0;
    if ((ptr + 16) <= pkt.size()) {
        try {
            planetWorldId = pkt.at<uint64_t>(ptr);
            ptr += 8;
            planetWorldTimestamp = pkt.at<uint64_t>(ptr);
            ptr += 8;
            fprintf(stderr, "planetWorldId=0x%016llx timestamp=0x%016llx: ptr now %u\n",
                    (unsigned long long)planetWorldId, (unsigned long long)planetWorldTimestamp, ptr);
        } catch (...) {
            fprintf(stderr, "TRACE: planetWorldId/timestamp at<uint64_t> threw\n");
            printf("drop_branch=other\n");
            return 0;
        }
    }

    // _doHELLO line 483-500: cryptField decrypts remainder, then reads numMoons and loops.
    //
    //   if (ptr < size()) {
    //       cryptField(peer->key(),ptr,size() - ptr);
    //       if ((ptr + 2) <= size()) {
    //           const unsigned int numMoons = at<uint16_t>(ptr);
    //           ptr += 2;
    //           for(unsigned int i=0;i<numMoons;++i) {
    //               if ((World::Type)(*this)[ptr++] == World::TYPE_MOON) { ... }
    //               ptr += 16;
    //           }
    //       }
    //   }
    //
    // Note: cryptField uses peer->key() (the DH-agreed session key) NOT a fresh key.
    // In _doHELLO's "new peer" branch, peer = topology->addPeer(newPeer), and
    // newPeer->key() is the same 32-byte key we computed above via controllerId.agree(id, key).
    //
    // The moon loop is the MOST LIKELY silent-drop site: if the decrypted numMoons
    // is a large uncontrolled 16-bit integer, the loop reads WAY past the packet,
    // throwing std::out_of_range from the Buffer bounds check, which propagates up
    // to tryDecode catch(...) as "unexpected exception in tryDecode()" ->
    // incomingPacketInvalid -> silent drop.
    if (ptr < pkt.size()) {
        const unsigned int remaining = pkt.size() - ptr;
        fprintf(stderr, "post-planet: %u bytes remaining after ptr=%u: entering cryptField+moon-loop region\n", remaining, ptr);
        // Reproduce cryptField using the same DH-agreed key we computed for dearmor.
        pkt.cryptField(key, ptr, remaining);
        fprintf(stderr, "cryptField decrypted %u bytes at offset %u\n", remaining, ptr);

        if ((ptr + 2) <= pkt.size()) {
            unsigned int numMoons = 0;
            try {
                numMoons = pkt.at<uint16_t>(ptr);
            } catch (...) {
                fprintf(stderr, "TRACE: at<uint16_t>(numMoons) threw: tryDecode catch(...) -> silent drop\n");
                printf("drop_branch=other\n");
                return 0;
            }
            ptr += 2;
            fprintf(stderr, "decrypted numMoons=%u (0x%04x): starting moon loop\n", numMoons, numMoons);
            // Compute expected bytes the loop needs: each iteration reads 1 byte (type) + 16 bytes (id+ts) = 17 bytes
            const unsigned int needed = numMoons * 17u;
            const unsigned int available = pkt.size() > ptr ? pkt.size() - ptr : 0;
            fprintf(stderr, "moon-loop needs %u bytes, has %u bytes available\n", needed, available);
            try {
                for (unsigned int i = 0; i < numMoons; ++i) {
                    uint8_t moonType = pkt[ptr++];
                    (void)moonType;
                    // Read 16 bytes (id+ts) via indexing.
                    if (ptr + 16 > pkt.size()) {
                        // This is the out_of_range case: upstream would throw
                        // via at<uint64_t> reads inside the std::pair construction.
                        throw std::out_of_range("moon-loop exceeds packet size");
                    }
                    ptr += 16;
                }
                fprintf(stderr, "moon loop completed cleanly (ptr=%u)\n", ptr);
            } catch (const std::exception &e) {
                fprintf(stderr, "TRACE: moon loop threw std::exception: %s\n", e.what());
                fprintf(stderr, "  upstream IncomingPacket.cpp:489-497 (inside _doHELLO body, NOT caught locally)\n");
                fprintf(stderr, "  propagates up to tryDecode catch(...) at IncomingPacket.cpp:160-164 -> incomingPacketInvalid \"unexpected exception\"\n");
                fprintf(stderr, "  SILENT DROP: no incomingPacketDroppedHELLO trace fires, member JSON stays unchanged\n");
                printf("drop_branch=other\n");
                return 0;
            } catch (...) {
                fprintf(stderr, "TRACE: moon loop threw unknown exception: silent drop\n");
                printf("drop_branch=other\n");
                return 0;
            }
        }
    }

    // _doHELLO line 535+: peer->setRemoteVersion and peer->received fire; OK(HELLO)
    // is built and sent. No more early-return paths. Accepted.
    fprintf(stderr, "TRACE: full _doHELLO body ran without throwing: OK(HELLO) would be sent, peer->setRemoteVersion + received fire\n");
    printf("drop_branch=accepted\n");
    return 0;
}
