import 'dart:async';
import 'dart:typed_data';

import 'embedded_node.dart';
import 'embedded_node_host.dart';

typedef EmbeddedNodeSessionFactory =
    EmbeddedNodeSession Function({
      required String identitySecret,
      required Uint8List planet,
      int initialPacketId,
      String? libraryPath,
    });

typedef EmbeddedDatagramEndpointFactory =
    Future<EmbeddedDatagramEndpoint> Function({
      required String host,
      required int port,
    });

typedef EmbeddedDefaultPlanetLoader =
    FutureOr<Uint8List> Function(String? libraryPath);

class EmbeddedNodeRuntimeConfig {
  const EmbeddedNodeRuntimeConfig({
    required this.dataDir,
    this.identityPath,
    this.planetPath,
    this.planet,
    this.udpHost = '0.0.0.0',
    this.udpPort = 9993,
    this.initialPacketId = 1,
    this.libraryPath,
    this.tickInterval = const Duration(milliseconds: 5000),
  });

  final String dataDir;
  final String? identityPath;
  final String? planetPath;
  final Uint8List? planet;
  final String udpHost;
  final int udpPort;
  final int initialPacketId;
  final String? libraryPath;
  final Duration tickInterval;

  String get resolvedIdentityPath =>
      identityPath ?? _joinPath(dataDir, 'identity.secret');

  List<String> get planetCandidatePaths {
    final path = planetPath;
    if (path != null) return <String>[path];
    return <String>[
      _joinPath(dataDir, 'planet.bin'),
      _joinPath(dataDir, 'planet'),
    ];
  }
}

abstract interface class EmbeddedNodeRuntimeLoader {
  Future<String> loadIdentitySecret(EmbeddedNodeRuntimeConfig config);
  Future<Uint8List?> loadPlanet(EmbeddedNodeRuntimeConfig config);
}

class EmbeddedNodeRuntime {
  const EmbeddedNodeRuntime({
    required this.config,
    required this.address,
    required this.host,
  });

  final EmbeddedNodeRuntimeConfig config;
  final Uint8List address;
  final EmbeddedNodeHost host;

  Stream<EmbeddedNodeAction> get actions => host.actions;

  Future<void> close() => host.close();
}

class EmbeddedNodeRuntimeStarter {
  const EmbeddedNodeRuntimeStarter({
    required EmbeddedNodeRuntimeLoader loader,
    required EmbeddedNodeSessionFactory sessionFactory,
    required EmbeddedDatagramEndpointFactory endpointFactory,
    required EmbeddedDefaultPlanetLoader defaultPlanetLoader,
    EmbeddedNodeClock clock = embeddedNodeSystemClockMs,
  }) : _loader = loader,
       _sessionFactory = sessionFactory,
       _endpointFactory = endpointFactory,
       _defaultPlanetLoader = defaultPlanetLoader,
       _clock = clock;

  final EmbeddedNodeRuntimeLoader _loader;
  final EmbeddedNodeSessionFactory _sessionFactory;
  final EmbeddedDatagramEndpointFactory _endpointFactory;
  final EmbeddedDefaultPlanetLoader _defaultPlanetLoader;
  final EmbeddedNodeClock _clock;

  Future<EmbeddedNodeRuntime> start(EmbeddedNodeRuntimeConfig config) async {
    final identitySecret = await _loader.loadIdentitySecret(config);
    final planet = await _loadPlanet(config);
    final session = _sessionFactory(
      identitySecret: identitySecret,
      planet: planet,
      initialPacketId: config.initialPacketId,
      libraryPath: config.libraryPath,
    );
    EmbeddedDatagramEndpoint? endpoint;
    EmbeddedNodeHost? host;
    try {
      endpoint = await _endpointFactory(
        host: config.udpHost,
        port: config.udpPort,
      );
      final address = session.address;
      host = EmbeddedNodeHost(
        session: session,
        endpoint: endpoint,
        clock: _clock,
        tickInterval: config.tickInterval,
      );
      await host.start();
      return EmbeddedNodeRuntime(config: config, address: address, host: host);
    } catch (_) {
      if (host != null) {
        await host.close();
      } else {
        session.close();
        await endpoint?.close();
      }
      rethrow;
    }
  }

  Future<Uint8List> _loadPlanet(EmbeddedNodeRuntimeConfig config) async {
    final planet = config.planet;
    if (planet != null) return Uint8List.fromList(planet);
    final stored = await _loader.loadPlanet(config);
    if (stored != null) return stored;
    return Uint8List.fromList(await _defaultPlanetLoader(config.libraryPath));
  }
}

String _joinPath(String dir, String file) {
  if (dir.endsWith('/') || dir.endsWith(r'\')) return '$dir$file';
  return '$dir/$file';
}
