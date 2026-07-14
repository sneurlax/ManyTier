import 'dart:async';
import 'dart:typed_data';

import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/embedded/embedded_virtual_network.dart';

class FakeEmbeddedVirtualNetworkFactory
    implements EmbeddedVirtualNetworkFactory {
  FakeEmbeddedVirtualNetworkFactory({
    this.supported = true,
    this.reason = 'virtual network unavailable',
  });

  final bool supported;
  final String reason;
  final List<EmbeddedVirtualNetworkConfig> creates =
      <EmbeddedVirtualNetworkConfig>[];
  final List<FakeEmbeddedVirtualNetworkInterface> interfaces =
      <FakeEmbeddedVirtualNetworkInterface>[];
  Object? nextCreateError;

  @override
  bool get isSupported => supported;

  @override
  String? get unsupportedReason => supported ? null : reason;

  @override
  Future<EmbeddedVirtualNetworkInterface> create(
    EmbeddedVirtualNetworkConfig config,
  ) async {
    creates.add(config);
    final error = nextCreateError;
    if (error != null) {
      if (error is Exception) throw error;
      throw EmbeddedNodeException('$error');
    }
    final interface = FakeEmbeddedVirtualNetworkInterface(config.networkId);
    interfaces.add(interface);
    return interface;
  }
}

class DisposableFakeEmbeddedVirtualNetworkFactory
    extends FakeEmbeddedVirtualNetworkFactory
    implements DisposableEmbeddedVirtualNetworkFactory {
  int disposeCalls = 0;

  @override
  Future<void> dispose() async {
    disposeCalls++;
  }
}

class FakeEmbeddedVirtualNetworkInterface
    implements EmbeddedVirtualNetworkInterface {
  FakeEmbeddedVirtualNetworkInterface(this.networkId);

  @override
  final int networkId;

  final StreamController<Uint8List> _packets =
      StreamController<Uint8List>.broadcast();
  final List<Uint8List> writes = <Uint8List>[];
  int closeCalls = 0;

  @override
  Stream<Uint8List> get packets => _packets.stream;

  @override
  Future<void> write(Uint8List packet) async {
    writes.add(Uint8List.fromList(packet));
  }

  Future<void> addPacket(List<int> packet) async {
    _packets.add(Uint8List.fromList(packet));
    await Future<void>.delayed(Duration.zero);
  }

  @override
  Future<void> close() async {
    closeCalls++;
    await _packets.close();
  }
}
