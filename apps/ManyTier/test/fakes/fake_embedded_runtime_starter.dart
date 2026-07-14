import 'dart:async';
import 'dart:typed_data';

import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/embedded/embedded_node_runtime.dart';
import 'package:manytier_app/src/state/embedded_runtime_lifecycle.dart';

class FakeEmbeddedRuntimeStarter implements EmbeddedRuntimeStarter {
  FakeEmbeddedRuntimeStarter({
    this.supported = true,
    this.defaultDir = '/tmp/manytier-test',
  });

  final bool supported;
  final String defaultDir;
  final List<EmbeddedNodeRuntimeConfig> starts = <EmbeddedNodeRuntimeConfig>[];
  final StreamController<EmbeddedNodeAction> actions =
      StreamController<EmbeddedNodeAction>.broadcast();
  final List<FakeVirtualPacket> virtualPackets = <FakeVirtualPacket>[];
  int closes = 0;
  Object? nextStartError;

  @override
  bool get isSupported => supported;

  @override
  String? get unsupportedReason =>
      supported ? null : 'embedded runtime unavailable';

  @override
  String get defaultDataDir => defaultDir;

  @override
  String preview(EmbeddedNodeRuntimeConfig config) {
    return 'Data ${config.dataDir}  UDP ${config.udpHost}:${config.udpPort}';
  }

  @override
  Future<StartedEmbeddedRuntime> start(EmbeddedNodeRuntimeConfig config) async {
    starts.add(config);
    final error = nextStartError;
    if (error != null) {
      if (error is Exception) throw error;
      throw Exception('$error');
    }
    return StartedEmbeddedRuntime(
      config: config,
      address: Uint8List.fromList(<int>[0xfa, 0xa9, 0, 0xda, 0x4a]),
      actions: actions.stream,
      receiveVirtualPacket: (networkId, packet) async {
        virtualPackets.add(FakeVirtualPacket(networkId, packet));
      },
      close: () async {
        closes++;
      },
    );
  }

  Future<void> dispose() => actions.close();
}

class FakeVirtualPacket {
  FakeVirtualPacket(this.networkId, Uint8List packet)
    : packet = Uint8List.fromList(packet);

  final int networkId;
  final Uint8List packet;
}
