import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/embedded/embedded_node_host.dart';

void main() {
  test('start bootstraps and sends UDP actions', () async {
    final driver = _HostTestDriver()
      ..bootstrapActions = <EmbeddedNodeAction>[
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.sendTo,
          socketAddress: EmbeddedSocketAddress.ipv4(203, 0, 113, 10, 9993),
          data: const <int>[1, 2, 3],
        ),
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.whoisNeeded,
          data: const <int>[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
          addressCount: 1,
        ),
      ];
    driver.sendWhoisActions = <EmbeddedNodeAction>[
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.sendTo,
        socketAddress: EmbeddedSocketAddress.ipv4(198, 51, 100, 10, 9993),
        data: const <int>[4, 5, 6],
      ),
    ];
    final endpoint = _FakeDatagramEndpoint();
    final emitted = <EmbeddedNodeAction>[];
    final host = EmbeddedNodeHost(
      session: EmbeddedNodeSession(driver),
      endpoint: endpoint,
      clock: () => 1000,
      tickInterval: Duration.zero,
    );
    addTearDown(host.close);
    host.actions.listen(emitted.add);

    await host.start();

    expect(driver.bootstrapCalls, <int>[1000]);
    expect(driver.sendWhoisCalls, <int>[1000]);
    expect(driver.lastWhoisAddresses, <List<int>>[
      <int>[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
    ]);
    expect(endpoint.sent, hasLength(2));
    expect(endpoint.sent[0].data, <int>[1, 2, 3]);
    expect(endpoint.sent[0].to.ipv4Octets, <int>[203, 0, 113, 10]);
    expect(endpoint.sent[1].data, <int>[4, 5, 6]);
    expect(endpoint.sent[1].to.ipv4Octets, <int>[198, 51, 100, 10]);
    expect(emitted, isEmpty);
    expect(driver.clearCalls, 2);
  });

  test('receiveDatagram forwards packet bytes into the node session', () async {
    final driver = _HostTestDriver()
      ..receiveActions = <EmbeddedNodeAction>[
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.sendTo,
          socketAddress: EmbeddedSocketAddress.ipv4(198, 51, 100, 2, 9993),
          data: const <int>[9, 9],
        ),
      ];
    final endpoint = _FakeDatagramEndpoint();
    final host = EmbeddedNodeHost(
      session: EmbeddedNodeSession(driver),
      endpoint: endpoint,
      clock: () => 2000,
      tickInterval: Duration.zero,
    );
    addTearDown(host.close);
    final from = EmbeddedSocketAddress.ipv4(192, 0, 2, 44, 9993);

    await host.receiveDatagram(
      EmbeddedDatagram(data: <int>[7, 8, 9], from: from),
    );

    expect(driver.receiveCalls, <int>[2000]);
    expect(driver.lastPacket, <int>[7, 8, 9]);
    expect(driver.lastFrom, same(from));
    expect(endpoint.sent.single.data, <int>[9, 9]);
    expect(endpoint.sent.single.to.ipv4Octets, <int>[198, 51, 100, 2]);
    expect(driver.clearCalls, 1);
  });

  test('datagrams from the endpoint are processed serially', () async {
    final driver = _HostTestDriver()
      ..receiveActions = <EmbeddedNodeAction>[
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.networkConfigured,
          networkId: 0x8056c2e21c000001,
          data: const <int>[1],
        ),
      ];
    final endpoint = _FakeDatagramEndpoint();
    var now = 3000;
    final emitted = <EmbeddedNodeAction>[];
    final host = EmbeddedNodeHost(
      session: EmbeddedNodeSession(driver),
      endpoint: endpoint,
      clock: () => now++,
      tickInterval: Duration.zero,
    );
    addTearDown(host.close);
    host.actions.listen(emitted.add);

    await host.start();
    endpoint.addIncoming(
      EmbeddedDatagram(
        data: <int>[1],
        from: EmbeddedSocketAddress.ipv4(203, 0, 113, 1, 9993),
      ),
    );
    endpoint.addIncoming(
      EmbeddedDatagram(
        data: <int>[2],
        from: EmbeddedSocketAddress.ipv4(203, 0, 113, 2, 9993),
      ),
    );
    await Future<void>.delayed(Duration.zero);
    await host.idle;

    expect(driver.receiveCalls, <int>[3001, 3002]);
    expect(driver.receivedPackets, <List<int>>[
      <int>[1],
      <int>[2],
    ]);
    expect(emitted, hasLength(2));
    expect(driver.clearCalls, 3);
  });

  test(
    'tick runs node maintenance and emits virtual-network actions',
    () async {
      final driver = _HostTestDriver()
        ..tickActions = <EmbeddedNodeAction>[
          EmbeddedNodeAction(
            kind: EmbeddedNodeActionKind.frameReceived,
            networkId: 0x8056c2e21c000001,
            srcMac: const <int>[1, 2, 3, 4, 5, 6],
            destMac: const <int>[6, 5, 4, 3, 2, 1],
            ethertype: 0x0800,
            data: const <int>[4, 5, 6],
          ),
        ];
      final endpoint = _FakeDatagramEndpoint();
      final emitted = <EmbeddedNodeAction>[];
      final host = EmbeddedNodeHost(
        session: EmbeddedNodeSession(driver),
        endpoint: endpoint,
        tickInterval: Duration.zero,
      );
      addTearDown(host.close);
      host.actions.listen(emitted.add);

      await host.tick(nowMs: 4000);

      expect(driver.tickCalls, <int>[4000]);
      expect(endpoint.sent, isEmpty);
      expect(emitted.single.kind, EmbeddedNodeActionKind.frameReceived);
      expect(emitted.single.data, <int>[4, 5, 6]);
      expect(driver.clearCalls, 1);
    },
  );

  test(
    'receiveVirtualPacket forwards IP packets into the node session',
    () async {
      final driver = _HostTestDriver()
        ..processVirtualFrameActions = <EmbeddedNodeAction>[
          EmbeddedNodeAction(
            kind: EmbeddedNodeActionKind.localReply,
            networkId: 0x8056c2e21c000001,
            ethertype: 0x0800,
            data: const <int>[0x45, 1],
          ),
        ];
      final endpoint = _FakeDatagramEndpoint();
      final emitted = <EmbeddedNodeAction>[];
      final host = EmbeddedNodeHost(
        session: EmbeddedNodeSession(driver),
        endpoint: endpoint,
        clock: () => 5000,
        tickInterval: Duration.zero,
      );
      addTearDown(host.close);
      host.actions.listen(emitted.add);

      await host.receiveVirtualPacket(
        0x8056c2e21c000001,
        Uint8List.fromList(<int>[0x45, 0, 0, 20]),
      );

      expect(driver.processVirtualFrameCalls, <int>[5000]);
      expect(driver.lastVirtualNetworkId, 0x8056c2e21c000001);
      expect(driver.lastVirtualEthertype, 0x0800);
      expect(driver.lastVirtualPayload, <int>[0x45, 0, 0, 20]);
      expect(endpoint.sent, isEmpty);
      expect(emitted.single.kind, EmbeddedNodeActionKind.localReply);
      expect(emitted.single.networkId, 0x8056c2e21c000001);
      expect(emitted.single.ethertype, 0x0800);
      expect(driver.clearCalls, 1);
    },
  );

  test('receiveVirtualPacket ignores empty and unknown packets', () async {
    final driver = _HostTestDriver();
    final host = EmbeddedNodeHost(
      session: EmbeddedNodeSession(driver),
      endpoint: _FakeDatagramEndpoint(),
      tickInterval: Duration.zero,
    );
    addTearDown(host.close);

    await host.receiveVirtualPacket(1, Uint8List(0));
    await host.receiveVirtualPacket(1, Uint8List.fromList(<int>[0x10]));

    expect(driver.processVirtualFrameCalls, isEmpty);
    expect(driver.clearCalls, 0);
  });

  test('close tears down the session and endpoint once', () async {
    final driver = _HostTestDriver();
    final endpoint = _FakeDatagramEndpoint();
    final host = EmbeddedNodeHost(
      session: EmbeddedNodeSession(driver),
      endpoint: endpoint,
      tickInterval: Duration.zero,
    );

    await host.close();
    await host.close();

    expect(driver.closeCalls, 1);
    expect(endpoint.closeCalls, 1);
    expect(() => host.tick(), throwsA(isA<EmbeddedNodeException>()));
  });
}

class _HostTestDriver implements EmbeddedNodeDriver {
  List<EmbeddedNodeAction> bootstrapActions = <EmbeddedNodeAction>[];
  List<EmbeddedNodeAction> tickActions = <EmbeddedNodeAction>[];
  List<EmbeddedNodeAction> receiveActions = <EmbeddedNodeAction>[];
  List<EmbeddedNodeAction> sendWhoisActions = <EmbeddedNodeAction>[];
  List<EmbeddedNodeAction> processVirtualFrameActions = <EmbeddedNodeAction>[];
  List<EmbeddedNodeAction> actions = <EmbeddedNodeAction>[];
  List<int> bootstrapCalls = <int>[];
  List<int> tickCalls = <int>[];
  List<int> receiveCalls = <int>[];
  List<int> sendWhoisCalls = <int>[];
  List<int> processVirtualFrameCalls = <int>[];
  List<List<int>> receivedPackets = <List<int>>[];
  List<List<int>> lastWhoisAddresses = <List<int>>[];
  Uint8List? lastPacket;
  EmbeddedSocketAddress? lastFrom;
  int? lastVirtualNetworkId;
  int? lastVirtualEthertype;
  Uint8List? lastVirtualPayload;
  int clearCalls = 0;
  int closeCalls = 0;

  @override
  Uint8List address() => Uint8List.fromList(<int>[0xfa, 0xa9, 0, 0xda, 0x4a]);

  @override
  int bootstrap(int nowMs) {
    bootstrapCalls.add(nowMs);
    actions = List<EmbeddedNodeAction>.from(bootstrapActions);
    return actions.length;
  }

  @override
  int tick(int nowMs) {
    tickCalls.add(nowMs);
    actions = List<EmbeddedNodeAction>.from(tickActions);
    return actions.length;
  }

  @override
  int receivePacket(Uint8List packet, EmbeddedSocketAddress from, int nowMs) {
    receiveCalls.add(nowMs);
    lastPacket = Uint8List.fromList(packet);
    receivedPackets.add(List<int>.from(packet));
    lastFrom = from;
    actions = List<EmbeddedNodeAction>.from(receiveActions);
    return actions.length;
  }

  @override
  int sendWhois(List<List<int>> addresses, int nowMs) {
    sendWhoisCalls.add(nowMs);
    lastWhoisAddresses = List<List<int>>.unmodifiable(
      addresses.map((address) => List<int>.unmodifiable(address)),
    );
    actions = List<EmbeddedNodeAction>.from(sendWhoisActions);
    return actions.length;
  }

  @override
  int processVirtualFrame(
    int networkId,
    int ethertype,
    Uint8List payload,
    int nowMs,
  ) {
    processVirtualFrameCalls.add(nowMs);
    lastVirtualNetworkId = networkId;
    lastVirtualEthertype = ethertype;
    lastVirtualPayload = Uint8List.fromList(payload);
    actions = List<EmbeddedNodeAction>.from(processVirtualFrameActions);
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

class _FakeDatagramEndpoint implements EmbeddedDatagramEndpoint {
  final StreamController<EmbeddedDatagram> _controller =
      StreamController<EmbeddedDatagram>.broadcast();
  final List<_SentDatagram> sent = <_SentDatagram>[];
  int closeCalls = 0;

  @override
  Stream<EmbeddedDatagram> get datagrams => _controller.stream;

  void addIncoming(EmbeddedDatagram datagram) {
    _controller.add(datagram);
  }

  @override
  Future<void> send(Uint8List data, EmbeddedSocketAddress address) async {
    sent.add(_SentDatagram(Uint8List.fromList(data), address));
  }

  @override
  Future<void> close() async {
    closeCalls += 1;
    await _controller.close();
  }
}

class _SentDatagram {
  const _SentDatagram(this.data, this.to);

  final Uint8List data;
  final EmbeddedSocketAddress to;
}
