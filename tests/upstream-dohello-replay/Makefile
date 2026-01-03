# DIAGNOSTIC TOOLING: not part of core manytier build. See README.md.
#
# Builds the _doHELLO offline-replay harness against upstream ZeroTierOne 1.14.2.
#
# Resolution order for the upstream source tree:
#   1. /tmp/ZT-1.14.2/ZeroTierOne-1.14.2/node  (default)
#   2. vendored/ZeroTierOne-1.14.2/node         (fallback; gitignored)

ZT_SRC ?= /tmp/ZT-1.14.2/ZeroTierOne-1.14.2/node
ifeq ($(wildcard $(ZT_SRC)/IncomingPacket.cpp),)
ZT_SRC := $(abspath vendored/ZeroTierOne-1.14.2/node)
endif

# Force the slow-crypto path in Packet.cpp to avoid pulling in ASM fast-path files.
# This keeps the TU list minimal and portable across x86_64 / aarch64 hosts.
CXX ?= g++
CXXFLAGS = -std=c++11 -O0 -g -Wall -Wno-unused-parameter -Wno-sign-compare \
           -Wno-unused-variable -Wno-reorder -Wno-missing-field-initializers \
           -Wno-unused-but-set-variable -Wno-maybe-uninitialized \
           -I$(ZT_SRC) -I$(ZT_SRC)/..
LDFLAGS = -pthread

# Compile the minimal set of upstream TUs that _doHELLO's decision ladder transitively needs:
# - Packet.cpp     : Packet::dearmor, Packet::armor, cryptField, compress/uncompress, _salsa20MangleKey
# - Identity.cpp   : Identity::locallyValidate, Identity::fromString (deserialize is inline template)
# - C25519.cpp     : key agreement (Identity::agree calls C25519::agree)
# - Salsa20.cpp    : Salsa20::crypt12 (used by dearmor slow path) and Salsa20::memxor
# - Poly1305.cpp   : Poly1305::compute (used by dearmor MAC check)
# - SHA512.cpp     : SHA512::hash (used by locallyValidate and fromString)
# - Utils.cpp      : Utils::getSecureRandom, hexStrToU64, stok, scopy, unhex, secureEq, burn, ...
# - InetAddress.cpp: InetAddress (referenced by Packet.hpp headers even though we don't use it)
# - AES.cpp        : AES::_initSW and AES class definitions (Packet.hpp references GMACSIVDecryptor;
#                    referenced from dearmor's cs==AES_GMAC_SIV branch which we don't hit but still links)
# - AES_aesni.cpp  : AES-NI intrinsics stub: present for symbol resolution; runtime not called
#
# Deliberately NOT included (these bring in Metrics/prometheus-cpp/Trace/Node/Topology):
#   IncomingPacket.cpp, Metrics.cpp, Trace.cpp, Node.cpp, Topology.cpp, Peer.cpp, Path.cpp,
#   Switch.cpp, Bond.cpp, SelfAwareness.cpp, PacketMultiplexer.cpp, Network.cpp, NetworkConfig.cpp,
#   Membership.cpp, Multicaster.cpp, CertificateOfMembership.cpp, CertificateOfOwnership.cpp,
#   Capability.cpp, Tag.cpp, Revocation.cpp, OutboundMulticast.cpp.
UPSTREAM_SRCS = \
    $(ZT_SRC)/Packet.cpp \
    $(ZT_SRC)/Identity.cpp \
    $(ZT_SRC)/C25519.cpp \
    $(ZT_SRC)/Salsa20.cpp \
    $(ZT_SRC)/Poly1305.cpp \
    $(ZT_SRC)/SHA512.cpp \
    $(ZT_SRC)/Utils.cpp \
    $(ZT_SRC)/InetAddress.cpp \
    $(ZT_SRC)/AES.cpp \
    $(ZT_SRC)/AES_aesni.cpp

all: replay

replay: replay.cpp $(UPSTREAM_SRCS)
	@echo "Building replay against upstream at: $(ZT_SRC)"
	@test -f $(ZT_SRC)/IncomingPacket.cpp || (echo "ERROR: upstream source not found at $(ZT_SRC); set ZT_SRC or create vendored/" && exit 1)
	$(CXX) $(CXXFLAGS) -o replay replay.cpp $(UPSTREAM_SRCS) $(LDFLAGS)

clean:
	rm -f replay *.o

.PHONY: all clean
