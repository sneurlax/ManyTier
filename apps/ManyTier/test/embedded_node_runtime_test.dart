import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/embedded/embedded_node_host.dart';
import 'package:manytier_app/src/embedded/embedded_node_runtime.dart';
import 'package:manytier_app/src/embedded/embedded_node_runtime_io.dart';

void main() {
  group('EmbeddedNodeRuntimeStarter', () {
    test('loads identity and stored planet before starting UDP host', () async {
      final driver = _RuntimeTestDriver()
        ..bootstrapActions = <EmbeddedNodeAction>[
          EmbeddedNodeAction(
            kind: EmbeddedNodeActionKind.sendTo,
            socketAddress: EmbeddedSocketAddress.ipv4(203, 0, 113, 1, 9993),
            data: const <int>[1, 2, 3],
          ),
        ];
      final loader = _FakeRuntimeLoader(
        identitySecret: 'faa900da4a:secret',
        storedPlanet: Uint8List.fromList(<int>[7, 7, 7]),
      );
      final endpoint = _FakeDatagramEndpoint();
      final sessionFactory = _RecordingSessionFactory(driver);
      final endpointFactory = _RecordingEndpointFactory(endpoint);
      final defaultLoader = _RecordingDefaultPlanetLoader(<int>[9, 9, 9]);
      final starter = EmbeddedNodeRuntimeStarter(
        loader: loader,
        sessionFactory: sessionFactory.create,
        endpointFactory: endpointFactory.create,
        defaultPlanetLoader: defaultLoader.load,
        clock: () => 1000,
      );
      final config = EmbeddedNodeRuntimeConfig(
        dataDir: '/tmp/manytier',
        udpHost: '127.0.0.1',
        udpPort: 4242,
        initialPacketId: 7,
        libraryPath: 'libzerotier_ffi.dylib',
        tickInterval: Duration.zero,
      );

      final runtime = await starter.start(config);
      addTearDown(runtime.close);

      expect(loader.identityPaths, <String>['/tmp/manytier/identity.secret']);
      expect(loader.planetCandidatePaths, <List<String>>[
        <String>['/tmp/manytier/planet.bin', '/tmp/manytier/planet'],
      ]);
      expect(sessionFactory.identitySecret, 'faa900da4a:secret');
      expect(sessionFactory.planet, <int>[7, 7, 7]);
      expect(sessionFactory.initialPacketId, 7);
      expect(sessionFactory.libraryPath, 'libzerotier_ffi.dylib');
      expect(endpointFactory.host, '127.0.0.1');
      expect(endpointFactory.port, 4242);
      expect(driver.bootstrapCalls, <int>[1000]);
      expect(endpoint.sent.single.data, <int>[1, 2, 3]);
      expect(endpoint.sent.single.to.ipv4Octets, <int>[203, 0, 113, 1]);
      expect(runtime.address, <int>[0xfa, 0xa9, 0, 0xda, 0x4a]);
      expect(defaultLoader.calls, isEmpty);

      await runtime.close();

      expect(driver.closeCalls, 1);
      expect(endpoint.closeCalls, 1);
    });

    test('uses explicit planet bytes before stored/default planets', () async {
      final driver = _RuntimeTestDriver();
      final loader = _FakeRuntimeLoader(
        identitySecret: 'identity',
        storedPlanet: Uint8List.fromList(<int>[1, 1, 1]),
      );
      final sessionFactory = _RecordingSessionFactory(driver);
      final defaultLoader = _RecordingDefaultPlanetLoader(<int>[9, 9, 9]);
      final runtime =
          await EmbeddedNodeRuntimeStarter(
            loader: loader,
            sessionFactory: sessionFactory.create,
            endpointFactory: _RecordingEndpointFactory(
              _FakeDatagramEndpoint(),
            ).create,
            defaultPlanetLoader: defaultLoader.load,
            clock: () => 1000,
          ).start(
            EmbeddedNodeRuntimeConfig(
              dataDir: '/tmp/manytier',
              planet: Uint8List.fromList(<int>[4, 5, 6]),
              tickInterval: Duration.zero,
            ),
          );
      addTearDown(runtime.close);

      expect(sessionFactory.planet, <int>[4, 5, 6]);
      expect(loader.planetCandidatePaths, isEmpty);
      expect(defaultLoader.calls, isEmpty);
    });

    test('falls back to the native default planet loader', () async {
      final driver = _RuntimeTestDriver();
      final loader = _FakeRuntimeLoader(identitySecret: 'identity');
      final sessionFactory = _RecordingSessionFactory(driver);
      final defaultLoader = _RecordingDefaultPlanetLoader(<int>[8, 8, 8]);
      final runtime =
          await EmbeddedNodeRuntimeStarter(
            loader: loader,
            sessionFactory: sessionFactory.create,
            endpointFactory: _RecordingEndpointFactory(
              _FakeDatagramEndpoint(),
            ).create,
            defaultPlanetLoader: defaultLoader.load,
            clock: () => 1000,
          ).start(
            const EmbeddedNodeRuntimeConfig(
              dataDir: '/tmp/manytier',
              libraryPath: 'custom-lib',
              tickInterval: Duration.zero,
            ),
          );
      addTearDown(runtime.close);

      expect(loader.planetCandidatePaths, <List<String>>[
        <String>['/tmp/manytier/planet.bin', '/tmp/manytier/planet'],
      ]);
      expect(defaultLoader.calls, <String?>['custom-lib']);
      expect(sessionFactory.planet, <int>[8, 8, 8]);
    });

    test('closes session and endpoint when host startup fails', () async {
      final driver = _RuntimeTestDriver()..throwOnBootstrap = true;
      final endpoint = _FakeDatagramEndpoint();
      final starter = EmbeddedNodeRuntimeStarter(
        loader: _FakeRuntimeLoader(identitySecret: 'identity'),
        sessionFactory: _RecordingSessionFactory(driver).create,
        endpointFactory: _RecordingEndpointFactory(endpoint).create,
        defaultPlanetLoader: _RecordingDefaultPlanetLoader(<int>[8]).load,
        clock: () => 1000,
      );

      await expectLater(
        starter.start(
          const EmbeddedNodeRuntimeConfig(
            dataDir: '/tmp/manytier',
            tickInterval: Duration.zero,
          ),
        ),
        throwsA(isA<EmbeddedNodeException>()),
      );

      expect(driver.closeCalls, 1);
      expect(endpoint.closeCalls, 1);
    });
  });

  group('IoEmbeddedNodeRuntimeLoader', () {
    test('loads identity and first available planet file', () async {
      final dir = await Directory.systemTemp.createTemp(
        'manytier_runtime_test',
      );
      addTearDown(() => dir.delete(recursive: true));
      await File('${dir.path}/identity.secret').writeAsString(' identity \n');
      await File('${dir.path}/planet.bin').writeAsBytes(<int>[1, 2, 3]);
      await File('${dir.path}/planet').writeAsBytes(<int>[4, 5, 6]);
      const loader = IoEmbeddedNodeRuntimeLoader();

      final identity = await loader.loadIdentitySecret(
        EmbeddedNodeRuntimeConfig(dataDir: dir.path),
      );
      final planet = await loader.loadPlanet(
        EmbeddedNodeRuntimeConfig(dataDir: dir.path),
      );

      expect(identity, 'identity');
      expect(planet, <int>[1, 2, 3]);
    });

    test('generates and persists identity files on first start', () async {
      final dir = await Directory.systemTemp.createTemp(
        'manytier_runtime_test',
      );
      addTearDown(() => dir.delete(recursive: true));
      final libraryPaths = <String?>[];
      final loader = IoEmbeddedNodeRuntimeLoader(
        identitySecretGenerator: ({String? libraryPath}) {
          libraryPaths.add(libraryPath);
          return 'abcde12345:0:public-key:secret-key';
        },
      );

      final identity = await loader.loadIdentitySecret(
        EmbeddedNodeRuntimeConfig(
          dataDir: dir.path,
          libraryPath: 'libzerotier_ffi.dylib',
        ),
      );

      expect(identity, 'abcde12345:0:public-key:secret-key');
      expect(libraryPaths, <String?>['libzerotier_ffi.dylib']);
      expect(
        await File('${dir.path}/identity.secret').readAsString(),
        'abcde12345:0:public-key:secret-key\n',
      );
      expect(
        await File('${dir.path}/identity.public').readAsString(),
        'abcde12345:0:public-key\n',
      );
    });

    test('rejects empty existing identity files', () async {
      final dir = await Directory.systemTemp.createTemp(
        'manytier_runtime_test',
      );
      addTearDown(() => dir.delete(recursive: true));
      const loader = IoEmbeddedNodeRuntimeLoader();

      await File('${dir.path}/identity.secret').writeAsString(' \n');

      await expectLater(
        loader.loadIdentitySecret(EmbeddedNodeRuntimeConfig(dataDir: dir.path)),
        throwsA(isA<EmbeddedNodeException>()),
      );
    });
  });
}

class _FakeRuntimeLoader implements EmbeddedNodeRuntimeLoader {
  _FakeRuntimeLoader({required this.identitySecret, this.storedPlanet});

  final String identitySecret;
  final Uint8List? storedPlanet;
  final List<String> identityPaths = <String>[];
  final List<List<String>> planetCandidatePaths = <List<String>>[];

  @override
  Future<String> loadIdentitySecret(EmbeddedNodeRuntimeConfig config) async {
    identityPaths.add(config.resolvedIdentityPath);
    return identitySecret;
  }

  @override
  Future<Uint8List?> loadPlanet(EmbeddedNodeRuntimeConfig config) async {
    planetCandidatePaths.add(List<String>.from(config.planetCandidatePaths));
    return storedPlanet == null ? null : Uint8List.fromList(storedPlanet!);
  }
}

class _RecordingSessionFactory {
  _RecordingSessionFactory(this.driver);

  final _RuntimeTestDriver driver;
  String? identitySecret;
  Uint8List? planet;
  int? initialPacketId;
  String? libraryPath;

  EmbeddedNodeSession create({
    required String identitySecret,
    required Uint8List planet,
    int initialPacketId = 1,
    String? libraryPath,
  }) {
    this.identitySecret = identitySecret;
    this.planet = Uint8List.fromList(planet);
    this.initialPacketId = initialPacketId;
    this.libraryPath = libraryPath;
    return EmbeddedNodeSession(driver);
  }
}

class _RecordingEndpointFactory {
  _RecordingEndpointFactory(this.endpoint);

  final _FakeDatagramEndpoint endpoint;
  String? host;
  int? port;

  Future<EmbeddedDatagramEndpoint> create({
    required String host,
    required int port,
  }) async {
    this.host = host;
    this.port = port;
    return endpoint;
  }
}

class _RecordingDefaultPlanetLoader {
  _RecordingDefaultPlanetLoader(this.bytes);

  final List<int> bytes;
  final List<String?> calls = <String?>[];

  Uint8List load(String? libraryPath) {
    calls.add(libraryPath);
    return Uint8List.fromList(bytes);
  }
}

class _RuntimeTestDriver implements EmbeddedNodeDriver {
  List<EmbeddedNodeAction> bootstrapActions = <EmbeddedNodeAction>[];
  List<EmbeddedNodeAction> actions = <EmbeddedNodeAction>[];
  List<int> bootstrapCalls = <int>[];
  int clearCalls = 0;
  int closeCalls = 0;
  bool throwOnBootstrap = false;

  @override
  Uint8List address() => Uint8List.fromList(<int>[0xfa, 0xa9, 0, 0xda, 0x4a]);

  @override
  int bootstrap(int nowMs) {
    if (throwOnBootstrap) {
      throw const EmbeddedNodeException('bootstrap failed');
    }
    bootstrapCalls.add(nowMs);
    actions = List<EmbeddedNodeAction>.from(bootstrapActions);
    return actions.length;
  }

  @override
  int tick(int nowMs) => 0;

  @override
  int receivePacket(Uint8List packet, EmbeddedSocketAddress from, int nowMs) {
    return 0;
  }

  @override
  int sendWhois(List<List<int>> addresses, int nowMs) => 0;

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
