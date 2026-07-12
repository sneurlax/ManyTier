import 'dart:io';
import 'dart:typed_data';

import 'embedded_datagram_endpoint.dart';
import 'embedded_node.dart';
import 'embedded_node_factory.dart';
import 'embedded_node_runtime.dart';

const bool embeddedNodeRuntimeEntryPointSupported = true;
const String? embeddedNodeRuntimeEntryPointUnsupportedReason = null;

typedef NativeIdentitySecretGenerator = String Function({String? libraryPath});

Future<EmbeddedNodeRuntime> startNativeEmbeddedNodeRuntime(
  EmbeddedNodeRuntimeConfig config,
) {
  return EmbeddedNodeRuntimeStarter(
    loader: const IoEmbeddedNodeRuntimeLoader(),
    sessionFactory: createNativeEmbeddedNodeSession,
    endpointFactory: ({required String host, required int port}) {
      return createRawSocketEmbeddedDatagramEndpoint(host: host, port: port);
    },
    defaultPlanetLoader: (libraryPath) =>
        loadNativeDefaultPlanet(libraryPath: libraryPath),
  ).start(config);
}

class IoEmbeddedNodeRuntimeLoader implements EmbeddedNodeRuntimeLoader {
  const IoEmbeddedNodeRuntimeLoader({
    this.identitySecretGenerator = generateNativeIdentitySecret,
  });

  final NativeIdentitySecretGenerator identitySecretGenerator;

  @override
  Future<String> loadIdentitySecret(EmbeddedNodeRuntimeConfig config) async {
    final file = File(config.resolvedIdentityPath);
    if (!await file.exists()) {
      final value = identitySecretGenerator(
        libraryPath: config.libraryPath,
      ).trim();
      if (value.isEmpty) {
        throw const EmbeddedNodeException(
          'Generated embedded node identity is empty.',
        );
      }
      await file.parent.create(recursive: true);
      await file.writeAsString('$value\n', flush: true);
      await File(
        _publicIdentityPath(file.path),
      ).writeAsString('${_publicIdentityFromSecret(value)}\n', flush: true);
      return value;
    }
    final value = (await file.readAsString()).trim();
    if (value.isEmpty) {
      throw EmbeddedNodeException(
        'Embedded node identity at ${file.path} is empty.',
      );
    }
    return value;
  }

  @override
  Future<Uint8List?> loadPlanet(EmbeddedNodeRuntimeConfig config) async {
    for (final path in config.planetCandidatePaths) {
      final file = File(path);
      if (await file.exists()) {
        return file.readAsBytes();
      }
    }
    return null;
  }
}

String _publicIdentityPath(String identityPath) {
  const suffix = '.secret';
  if (identityPath.endsWith(suffix)) {
    return '${identityPath.substring(0, identityPath.length - suffix.length)}.public';
  }
  return '$identityPath.public';
}

String _publicIdentityFromSecret(String secret) {
  final parts = secret.trim().split(':');
  if (parts.length < 3) {
    throw const EmbeddedNodeException(
      'Generated embedded node identity is not in identity.secret format.',
    );
  }
  return parts.take(3).join(':');
}
