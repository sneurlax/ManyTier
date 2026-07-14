import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/embedded/embedded_virtual_network.dart';
import 'package:manytier_app/src/embedded/embedded_virtual_network_channel.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('com.manytier.test/virtual_networks');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
    channel.setMethodCallHandler(null);
  });

  test('create, write, and close use the platform channel contract', () async {
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          if (call.method == 'createVirtualNetwork') {
            return <String, Object?>{'interfaceId': 'native-1'};
          }
          return null;
        });
    final factory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
    );
    addTearDown(factory.dispose);

    final interface = await factory.create(_config());
    await interface.write(Uint8List.fromList(<int>[0x45, 1]));
    await interface.close();

    expect(calls.map((call) => call.method), <String>[
      'createVirtualNetwork',
      'writeVirtualPacket',
      'closeVirtualNetwork',
    ]);
    final createArgs = _args(calls[0]);
    expect(createArgs['networkIdHex'], '8056c2e21c000001');
    expect(createArgs['interfaceName'], 'zt00000100da4a');
    expect(createArgs['nodeAddress'], <int>[0xfa, 0xa9, 0, 0xda, 0x4a]);
    expect(createArgs['dictData'], <int>[1, 2, 3]);
    expect(createArgs['mtu'], 1280);

    final addresses = createArgs['managedAddresses']! as List<Object?>;
    expect(addresses, hasLength(2));
    expect(_map(addresses[0])['family'], 'ipv4');
    expect(_map(addresses[0])['address'], '10.147.20.7');
    expect(_map(addresses[0])['prefixLength'], 24);
    expect(_map(addresses[1])['family'], 'ipv6');
    expect(_map(addresses[1])['address'], 'fd00::7');
    expect(_map(addresses[1])['prefixLength'], 64);

    final routes = createArgs['routes']! as List<Object?>;
    expect(routes, hasLength(1));
    expect(_map(_map(routes.single)['target'])['address'], '10.147.20.0');
    expect(_map(_map(routes.single)['gateway'])['address'], '10.147.20.1');
    expect(_map(routes.single)['flags'], 3);

    expect(_args(calls[1])['interfaceId'], 'native-1');
    expect(_args(calls[1])['networkIdHex'], '8056c2e21c000001');
    expect(_args(calls[1])['packet'], <int>[0x45, 1]);
    expect(_args(calls[2])['interfaceId'], 'native-1');
  });

  test('native virtualPacket callbacks emit interface packets', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'createVirtualNetwork') return 'native-1';
          return null;
        });
    final factory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
    );
    addTearDown(factory.dispose);

    final interface = await factory.create(_config());
    final packet = expectLater(interface.packets, emits(<int>[0x45, 0, 0, 20]));

    await factory.handleNativeMethodCall(
      MethodCall('virtualPacket', <String, Object?>{
        'interfaceId': 'native-1',
        'packet': Uint8List.fromList(<int>[0x45, 0, 0, 20]),
      }),
    );

    await packet;
  });

  test('checkSupport reports native capability responses', () async {
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return <String, Object?>{
            'supported': true,
            'platform': 'linux',
            'reason': '',
            'device': 'tun',
          };
        });
    final factory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
    );
    addTearDown(factory.dispose);

    final support = await factory.checkSupport();

    expect(calls.map((call) => call.method), <String>['virtualNetworkSupport']);
    expect(support.isSupported, isTrue);
    expect(support.platform, 'linux');
    expect(support.reason, isNull);
    expect(support.details['device'], 'tun');
  });

  test('checkSupport reports native unsupported responses', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          return <String, Object?>{
            'supported': false,
            'platform': 'macos',
            'reason': 'Network Extension packet tunnel missing',
          };
        });
    final factory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
    );
    addTearDown(factory.dispose);

    final support = await factory.checkSupport();

    expect(support.isSupported, isFalse);
    expect(support.platform, 'macos');
    expect(support.reason, 'Network Extension packet tunnel missing');
  });

  test('checkSupport reports missing or disabled native handlers', () async {
    final missingFactory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
    );
    addTearDown(missingFactory.dispose);

    final missing = await missingFactory.checkSupport();
    expect(missing.isSupported, isFalse);
    expect(missing.reason, 'Native virtual network handler is unavailable.');

    final disabledFactory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
      supported: false,
      unsupportedReason: 'disabled for this platform',
    );
    addTearDown(disabledFactory.dispose);

    final disabled = await disabledFactory.checkSupport();
    expect(disabled.isSupported, isFalse);
    expect(disabled.reason, 'disabled for this platform');
  });

  test(
    'checkSupport converts native probe failures to unsupported results',
    () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            throw PlatformException(
              code: 'probe-failed',
              message: 'support probe failed',
              details: <String, Object?>{'platform': 'macos'},
            );
          });
      final factory = MethodChannelEmbeddedVirtualNetworkFactory(
        channel: channel,
      );
      addTearDown(factory.dispose);

      final support = await factory.checkSupport();

      expect(support.isSupported, isFalse);
      expect(support.reason, 'support probe failed');
      expect(support.details['code'], 'probe-failed');
      expect(_map(support.details['details'])['platform'], 'macos');
    },
  );

  test('create reports missing or failing native handlers', () async {
    final missingFactory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
    );
    addTearDown(missingFactory.dispose);

    await expectLater(
      missingFactory.create(_config()),
      throwsA(isA<EmbeddedNodeException>()),
    );

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          throw PlatformException(code: 'tun-create-failed', message: 'no TUN');
        });
    final failingFactory = MethodChannelEmbeddedVirtualNetworkFactory(
      channel: channel,
    );
    addTearDown(failingFactory.dispose);

    await expectLater(
      failingFactory.create(_config()),
      throwsA(
        isA<EmbeddedNodeException>().having(
          (e) => e.message,
          'message',
          'no TUN',
        ),
      ),
    );
  });
}

EmbeddedVirtualNetworkConfig _config() {
  return EmbeddedVirtualNetworkConfig(
    networkId: 0x8056c2e21c000001,
    nodeAddress: Uint8List.fromList(<int>[0xfa, 0xa9, 0, 0xda, 0x4a]),
    dictData: Uint8List.fromList(<int>[1, 2, 3]),
    settings: EmbeddedVirtualNetworkSettings(
      mtu: 1280,
      managedAddresses: <EmbeddedVirtualNetworkAddress>[
        EmbeddedVirtualNetworkAddress(
          family: EmbeddedVirtualNetworkAddressFamily.ipv4,
          bytes: <int>[10, 147, 20, 7],
          prefixLength: 24,
        ),
        EmbeddedVirtualNetworkAddress(
          family: EmbeddedVirtualNetworkAddressFamily.ipv6,
          bytes: <int>[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
          prefixLength: 64,
        ),
      ],
      routes: <EmbeddedVirtualNetworkRoute>[
        EmbeddedVirtualNetworkRoute(
          target: EmbeddedVirtualNetworkAddress(
            family: EmbeddedVirtualNetworkAddressFamily.ipv4,
            bytes: <int>[10, 147, 20, 0],
            prefixLength: 24,
          ),
          gateway: EmbeddedVirtualNetworkAddress(
            family: EmbeddedVirtualNetworkAddressFamily.ipv4,
            bytes: <int>[10, 147, 20, 1],
            prefixLength: 0,
          ),
          flags: 3,
        ),
      ],
    ),
  );
}

Map<Object?, Object?> _args(MethodCall call) => _map(call.arguments);

Map<Object?, Object?> _map(Object? value) {
  if (value is Map<Object?, Object?>) return value;
  if (value is Map) return Map<Object?, Object?>.from(value);
  fail('Expected a map, got $value');
}
