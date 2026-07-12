import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:manytier_app/src/embedded/embedded_node.dart';

void main() {
  group('EmbeddedSocketAddress', () {
    test('constructs IPv4 addresses with zero-padded storage', () {
      final address = EmbeddedSocketAddress.ipv4(192, 0, 2, 10, 9993);

      expect(address.family, 4);
      expect(address.ipv4Octets, <int>[192, 0, 2, 10]);
      expect(address.address, <int>[
        192,
        0,
        2,
        10,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
      ]);
      expect(address.port, 9993);
    });

    test('rejects invalid address values', () {
      expect(
        () => EmbeddedSocketAddress(
          family: 5,
          address: List<int>.filled(16, 0),
          port: 1,
        ),
        throwsArgumentError,
      );
      expect(
        () => EmbeddedSocketAddress.ipv6(<int>[1, 2, 3], 1),
        throwsArgumentError,
      );
      expect(
        () => EmbeddedSocketAddress.ipv4(192, 0, 2, 1, 70000),
        throwsRangeError,
      );
      expect(
        () => EmbeddedSocketAddress.ipv4(192, 0, 2, 300, 9993),
        throwsRangeError,
      );
    });
  });

  group('EmbeddedNodeActionKind', () {
    test('maps FFI action codes and falls back to unknown', () {
      expect(
        EmbeddedNodeActionKind.fromFfiCode(
          EmbeddedNodeActionKind.sendTo.ffiCode,
        ),
        EmbeddedNodeActionKind.sendTo,
      );
      expect(
        EmbeddedNodeActionKind.fromFfiCode(999),
        EmbeddedNodeActionKind.unknown,
      );
    });
  });

  group('EmbeddedNodeSession', () {
    test('exposes address and collects bootstrap actions by count', () {
      final driver = _FakeEmbeddedNodeDriver();
      final session = EmbeddedNodeSession(driver);

      expect(
        session.address,
        Uint8List.fromList(<int>[0xfa, 0xa9, 0, 0xda, 0x4a]),
      );

      final actions = session.bootstrap(1000);

      expect(driver.bootstrapCalls, <int>[1000]);
      expect(actions, hasLength(2));
      expect(actions.first.kind, EmbeddedNodeActionKind.sendTo);
      expect(actions.first.socketAddress?.ipv4Octets, <int>[203, 0, 113, 1]);
      expect(actions.first.data, <int>[1, 2, 3]);
      expect(actions.last.kind, EmbeddedNodeActionKind.whoisNeeded);
      expect(actions.last.addressCount, 1);
      expect(actions.last.data, <int>[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    });

    test('passes received packets and socket addresses to the driver', () {
      final driver = _FakeEmbeddedNodeDriver();
      final session = EmbeddedNodeSession(driver);
      final from = EmbeddedSocketAddress.ipv6(List<int>.filled(16, 1), 9993);
      final packet = Uint8List.fromList(<int>[9, 8, 7]);

      final actions = session.receivePacket(packet, from, 2000);

      expect(driver.lastPacket, <int>[9, 8, 7]);
      expect(driver.lastFrom, same(from));
      expect(driver.receiveCalls, <int>[2000]);
      expect(actions.single.kind, EmbeddedNodeActionKind.frameReceived);
      expect(actions.single.networkId, 0x8056c2e21c000001);
      expect(actions.single.srcMac, <int>[1, 2, 3, 4, 5, 6]);
      expect(actions.single.destMac, <int>[6, 5, 4, 3, 2, 1]);
      expect(actions.single.ethertype, 0x0800);
      expect(actions.single.data, <int>[7, 7, 7]);
    });

    test('sendWhois validates addresses and collects resulting actions', () {
      final driver = _FakeEmbeddedNodeDriver();
      final session = EmbeddedNodeSession(driver);

      final actions = session.sendWhois(<List<int>>[
        <int>[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
      ], 2500);

      expect(driver.sendWhoisCalls, <int>[2500]);
      expect(driver.lastWhoisAddresses, <List<int>>[
        <int>[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
      ]);
      expect(actions.single.kind, EmbeddedNodeActionKind.sendTo);
      expect(actions.single.data, <int>[4, 5, 6]);

      expect(
        () => session.sendWhois(<List<int>>[
          <int>[1, 2, 3],
        ], 2600),
        throwsArgumentError,
      );
    });

    test('zeroTierAddressList decodes flat WHOIS action payloads', () {
      final action = EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.whoisNeeded,
        data: const <int>[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        addressCount: 2,
      );

      expect(action.zeroTierAddressList, <List<int>>[
        <int>[1, 2, 3, 4, 5],
        <int>[6, 7, 8, 9, 10],
      ]);
      expect(
        () => action.zeroTierAddressList.first.add(11),
        throwsUnsupportedError,
      );

      final malformed = EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.whoisNeeded,
        data: const <int>[1, 2, 3],
        addressCount: 1,
      );
      expect(
        () => malformed.zeroTierAddressList,
        throwsA(isA<EmbeddedNodeException>()),
      );
    });

    test('returns pending actions and clears them explicitly', () {
      final driver = _FakeEmbeddedNodeDriver()
        ..actions = <EmbeddedNodeAction>[
          EmbeddedNodeAction(
            kind: EmbeddedNodeActionKind.pathNegotiationReceived,
            ztAddress: const <int>[1, 2, 3, 4, 5],
            utility: -10,
          ),
        ];
      final session = EmbeddedNodeSession(driver);

      expect(session.pendingActions.single.utility, -10);

      session.clearActions();

      expect(driver.clearCalls, 1);
      expect(session.pendingActions, isEmpty);
    });

    test('close is idempotent and prevents future driver access', () {
      final driver = _FakeEmbeddedNodeDriver();
      final session = EmbeddedNodeSession(driver);

      session.close();
      session.close();

      expect(driver.closeCalls, 1);
      expect(() => session.address, throwsA(isA<EmbeddedNodeException>()));
      expect(() => session.bootstrap(1), throwsA(isA<EmbeddedNodeException>()));
      expect(() => session.tick(1), throwsA(isA<EmbeddedNodeException>()));
      expect(
        () => session.receivePacket(
          Uint8List(0),
          EmbeddedSocketAddress.ipv4(127, 0, 0, 1, 9993),
          1,
        ),
        throwsA(isA<EmbeddedNodeException>()),
      );
      expect(
        () => session.pendingActions,
        throwsA(isA<EmbeddedNodeException>()),
      );
      expect(
        () => session.clearActions(),
        throwsA(isA<EmbeddedNodeException>()),
      );
    });
  });

  group('EmbeddedNodeAction', () {
    test('defensively copies mutable byte lists', () {
      final data = <int>[1, 2, 3];
      final action = EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.remoteTraceReceived,
        data: data,
      );

      data[0] = 9;

      expect(action.data, <int>[1, 2, 3]);
      expect(() => action.data.add(4), throwsUnsupportedError);
    });

    test('rejects invalid fixed-width addresses', () {
      expect(
        () => EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.userMessageReceived,
          ztAddress: const <int>[1, 2, 3],
        ),
        throwsArgumentError,
      );
    });
  });
}

class _FakeEmbeddedNodeDriver implements EmbeddedNodeDriver {
  List<EmbeddedNodeAction> actions = <EmbeddedNodeAction>[];
  List<int> bootstrapCalls = <int>[];
  List<int> tickCalls = <int>[];
  List<int> receiveCalls = <int>[];
  List<int> sendWhoisCalls = <int>[];
  Uint8List? lastPacket;
  EmbeddedSocketAddress? lastFrom;
  List<List<int>> lastWhoisAddresses = <List<int>>[];
  int clearCalls = 0;
  int closeCalls = 0;

  @override
  Uint8List address() => Uint8List.fromList(<int>[0xfa, 0xa9, 0, 0xda, 0x4a]);

  @override
  int bootstrap(int nowMs) {
    bootstrapCalls.add(nowMs);
    actions = <EmbeddedNodeAction>[
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.sendTo,
        socketAddress: EmbeddedSocketAddress.ipv4(203, 0, 113, 1, 9993),
        data: const <int>[1, 2, 3],
      ),
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.whoisNeeded,
        data: const <int>[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        addressCount: 1,
      ),
    ];
    return actions.length;
  }

  @override
  int tick(int nowMs) {
    tickCalls.add(nowMs);
    actions = <EmbeddedNodeAction>[];
    return actions.length;
  }

  @override
  int receivePacket(Uint8List packet, EmbeddedSocketAddress from, int nowMs) {
    receiveCalls.add(nowMs);
    lastPacket = Uint8List.fromList(packet);
    lastFrom = from;
    actions = <EmbeddedNodeAction>[
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.frameReceived,
        networkId: 0x8056c2e21c000001,
        srcMac: const <int>[1, 2, 3, 4, 5, 6],
        destMac: const <int>[6, 5, 4, 3, 2, 1],
        ethertype: 0x0800,
        data: const <int>[7, 7, 7],
      ),
    ];
    return actions.length;
  }

  @override
  int sendWhois(List<List<int>> addresses, int nowMs) {
    sendWhoisCalls.add(nowMs);
    lastWhoisAddresses = List<List<int>>.unmodifiable(
      addresses.map((address) => List<int>.unmodifiable(address)),
    );
    actions = <EmbeddedNodeAction>[
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.sendTo,
        socketAddress: EmbeddedSocketAddress.ipv4(203, 0, 113, 2, 9993),
        data: const <int>[4, 5, 6],
      ),
    ];
    return actions.length;
  }

  @override
  int actionCount() => actions.length;

  @override
  EmbeddedNodeAction actionAt(int index) => actions[index];

  @override
  void clearActions() {
    clearCalls += 1;
    actions = <EmbeddedNodeAction>[];
  }

  @override
  void close() {
    closeCalls += 1;
  }
}
