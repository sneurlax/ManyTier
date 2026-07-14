import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/embedded/embedded_virtual_network.dart';

import 'fakes/fake_embedded_virtual_network.dart';

void main() {
  test('NetworkConfigured creates an interface with copied config', () async {
    final factory = FakeEmbeddedVirtualNetworkFactory();
    final forwarded = <({int networkId, Uint8List packet})>[];
    final nodeAddress = Uint8List.fromList(<int>[0xfa, 0xa9, 0, 0xda, 0x4a]);
    final dictData = _dictionary(<String, List<int>>{
      'mtu': '500'.codeUnits,
      'I': _inet4(10, 147, 20, 7, 24),
    });
    final coordinator = EmbeddedVirtualNetworkCoordinator(
      factory: factory,
      nodeAddress: nodeAddress,
      packetSink: (networkId, packet) async {
        forwarded.add((networkId: networkId, packet: packet));
      },
    );
    addTearDown(coordinator.close);

    nodeAddress[0] = 0;
    await coordinator.handleAction(
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.networkConfigured,
        networkId: 0x8056c2e21c000001,
        data: dictData,
      ),
    );

    expect(factory.creates, hasLength(1));
    expect(factory.creates.single.networkId, 0x8056c2e21c000001);
    expect(factory.creates.single.nodeAddress, <int>[
      0xfa,
      0xa9,
      0,
      0xda,
      0x4a,
    ]);
    expect(factory.creates.single.dictData, dictData);
    expect(factory.creates.single.interfaceName, 'zt00000100da4a');
    expect(factory.creates.single.settings.mtu, 1280);
    expect(
      factory.creates.single.settings.managedAddresses.single.cidr,
      '10.147.20.7/24',
    );
    expect(coordinator.interfaceCount, 1);

    await factory.interfaces.single.addPacket(<int>[0x45, 0, 0, 20]);

    expect(forwarded.single.networkId, 0x8056c2e21c000001);
    expect(forwarded.single.packet, <int>[0x45, 0, 0, 20]);
  });

  test('config parses managed addresses and routes from dictionary bytes', () {
    final routeBytes = <int>[
      ..._inet4(10, 147, 20, 0, 24),
      ..._inetNull(),
      0,
      0,
      ..._inet6(<int>[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 64),
      ..._inet6(<int>[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 0),
      0x12,
      0x34,
    ];
    final config = EmbeddedVirtualNetworkConfig(
      networkId: 0xd73835e5b10894e0,
      nodeAddress: Uint8List.fromList(<int>[0x51, 0x8d, 0x35, 0xae, 0x76]),
      dictData: Uint8List.fromList(
        _dictionary(<String, List<int>>{
          'mtu': 'af0'.codeUnits,
          'I': <int>[
            ..._inet4(10, 147, 20, 7, 24),
            ..._inet6(<int>[
              0xfd,
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
              0,
              0,
              7,
            ], 64),
          ],
          'RT': routeBytes,
        }),
      ),
    );

    expect(config.interfaceName, 'zt0894e035ae76');
    expect(config.settings.mtu, 2800);
    expect(
      config.settings.managedAddresses.map((address) => address.cidr),
      <String>['10.147.20.7/24', 'fd00::7/64'],
    );
    expect(
      () => config.settings.managedAddresses.add(
        config.settings.managedAddresses.first,
      ),
      throwsUnsupportedError,
    );
    expect(config.settings.routes, hasLength(2));
    expect(config.settings.routes[0].target.cidr, '10.147.20.0/24');
    expect(config.settings.routes[0].gateway, isNull);
    expect(config.settings.routes[0].flags, 0);
    expect(config.settings.routes[1].target.cidr, 'fd00::/64');
    expect(config.settings.routes[1].gateway?.address, 'fd00::1');
    expect(config.settings.routes[1].flags, 0x1234);
  });

  test('config falls back to defaults for malformed dictionaries', () {
    final config = EmbeddedVirtualNetworkConfig(
      networkId: 7,
      nodeAddress: Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
      dictData: Uint8List.fromList('not-a-dict-entry'.codeUnits),
    );

    expect(config.interfaceName, 'zt000007030405');
    expect(config.settings.mtu, EmbeddedVirtualNetworkSettings.defaultMtu);
    expect(config.settings.managedAddresses, isEmpty);
    expect(config.settings.routes, isEmpty);
  });

  test('embeddedVirtualNetworkName validates the node address', () {
    expect(
      () => embeddedVirtualNetworkName(1, <int>[1, 2, 3]),
      throwsArgumentError,
    );
    expect(
      () => embeddedVirtualNetworkName(1, <int>[1, 2, 300, 4, 5]),
      throwsRangeError,
    );
  });

  test(
    'FrameReceived and LocalReply write to the configured interface',
    () async {
      final factory = FakeEmbeddedVirtualNetworkFactory();
      final coordinator = EmbeddedVirtualNetworkCoordinator(
        factory: factory,
        nodeAddress: Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
        packetSink: (_, _) async {},
      );
      addTearDown(coordinator.close);

      await coordinator.handleAction(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.networkConfigured,
          networkId: 7,
        ),
      );
      await coordinator.handleAction(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.frameReceived,
          networkId: 7,
          ethertype: 0x0800,
          data: const <int>[0x45, 1],
        ),
      );
      await coordinator.handleAction(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.localReply,
          networkId: 7,
          ethertype: 0x0806,
          data: const <int>[0xaa, 0xbb],
        ),
      );
      await coordinator.handleAction(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.frameReceived,
          networkId: 8,
          data: const <int>[9, 9],
        ),
      );

      expect(factory.interfaces.single.writes, hasLength(2));
      expect(factory.interfaces.single.writes[0], <int>[0x45, 1]);
      expect(factory.interfaces.single.writes[1], <int>[0xaa, 0xbb]);
    },
  );

  test(
    'repeated NetworkConfigured does not replace an existing interface',
    () async {
      final factory = FakeEmbeddedVirtualNetworkFactory();
      final coordinator = EmbeddedVirtualNetworkCoordinator(
        factory: factory,
        nodeAddress: Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
        packetSink: (_, _) async {},
      );
      addTearDown(coordinator.close);

      await coordinator.handleAction(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.networkConfigured,
          networkId: 7,
          data: const <int>[1],
        ),
      );
      await coordinator.handleAction(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.networkConfigured,
          networkId: 7,
          data: const <int>[2],
        ),
      );

      expect(factory.creates, hasLength(1));
      expect(coordinator.interfaceCount, 1);
    },
  );

  test('unsupported factories leave network actions as no-ops', () async {
    final factory = FakeEmbeddedVirtualNetworkFactory(supported: false);
    final coordinator = EmbeddedVirtualNetworkCoordinator(
      factory: factory,
      nodeAddress: Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
      packetSink: (_, _) async {},
    );
    addTearDown(coordinator.close);

    await coordinator.handleAction(
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.networkConfigured,
        networkId: 7,
      ),
    );
    await coordinator.handleAction(
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.frameReceived,
        networkId: 7,
        data: const <int>[1],
      ),
    );

    expect(factory.creates, isEmpty);
    expect(coordinator.interfaceCount, 0);
  });

  test('close tears down interfaces and stops packet forwarding', () async {
    final factory = FakeEmbeddedVirtualNetworkFactory();
    final forwarded = <({int networkId, Uint8List packet})>[];
    final coordinator = EmbeddedVirtualNetworkCoordinator(
      factory: factory,
      nodeAddress: Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
      packetSink: (networkId, packet) async {
        forwarded.add((networkId: networkId, packet: packet));
      },
    );

    await coordinator.handleAction(
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.networkConfigured,
        networkId: 7,
      ),
    );
    await coordinator.close();
    await coordinator.close();

    expect(factory.interfaces.single.closeCalls, 1);
    expect(coordinator.interfaceCount, 0);
    expect(forwarded, isEmpty);
  });
}

List<int> _dictionary(Map<String, List<int>> entries) {
  final bytes = <int>[];
  var first = true;
  for (final entry in entries.entries) {
    if (!first) {
      bytes.add(0x0a);
    }
    first = false;
    bytes.addAll(entry.key.codeUnits);
    bytes.add(0x3d);
    for (final byte in entry.value) {
      switch (byte) {
        case 0:
          bytes.addAll(r'\0'.codeUnits);
        case 0x0d:
          bytes.addAll(r'\r'.codeUnits);
        case 0x0a:
          bytes.addAll(r'\n'.codeUnits);
        case 0x5c:
          bytes.addAll(r'\\'.codeUnits);
        case 0x3d:
          bytes.addAll(r'\e'.codeUnits);
        default:
          bytes.add(byte);
      }
    }
  }
  return bytes;
}

List<int> _inetNull() => <int>[0];

List<int> _inet4(int a, int b, int c, int d, int prefixLength) {
  return <int>[0x04, a, b, c, d, prefixLength >> 8, prefixLength & 0xff];
}

List<int> _inet6(List<int> bytes, int prefixLength) {
  return <int>[0x06, ...bytes, prefixLength >> 8, prefixLength & 0xff];
}
