/// App-managed lifecycle helpers for the embedded node runtime.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:hooks_riverpod/hooks_riverpod.dart';

import '../embedded/embedded_node.dart';
import '../embedded/embedded_node_runtime.dart';
import '../embedded/embedded_node_runtime_factory.dart';
import '../embedded/embedded_virtual_network.dart';
import 'service_lifecycle.dart';

class StartedEmbeddedRuntime {
  const StartedEmbeddedRuntime({
    required this.config,
    required this.address,
    required this.actions,
    required this.receiveVirtualPacket,
    required this.close,
  });

  factory StartedEmbeddedRuntime.fromRuntime(EmbeddedNodeRuntime runtime) {
    return StartedEmbeddedRuntime(
      config: runtime.config,
      address: runtime.address,
      actions: runtime.actions,
      receiveVirtualPacket: (networkId, packet) {
        return runtime.host.receiveVirtualPacket(networkId, packet);
      },
      close: runtime.close,
    );
  }

  final EmbeddedNodeRuntimeConfig config;
  final Uint8List address;
  final Stream<EmbeddedNodeAction> actions;
  final EmbeddedVirtualPacketSink receiveVirtualPacket;
  final Future<void> Function() close;

  String get addressHex => _hex(address);
}

abstract interface class EmbeddedRuntimeStarter {
  bool get isSupported;
  String? get unsupportedReason;
  String get defaultDataDir;

  String preview(EmbeddedNodeRuntimeConfig config);
  Future<StartedEmbeddedRuntime> start(EmbeddedNodeRuntimeConfig config);
}

class NativeEmbeddedRuntimeStarter implements EmbeddedRuntimeStarter {
  NativeEmbeddedRuntimeStarter({
    required this.defaultDataDir,
    Future<EmbeddedNodeRuntime> Function(EmbeddedNodeRuntimeConfig config)?
    startRuntime,
  }) : _startRuntime = startRuntime ?? startNativeEmbeddedNodeRuntime;

  final Future<EmbeddedNodeRuntime> Function(EmbeddedNodeRuntimeConfig config)
  _startRuntime;

  @override
  final String defaultDataDir;

  @override
  bool get isSupported => embeddedNodeRuntimeEntryPointSupported;

  @override
  String? get unsupportedReason =>
      embeddedNodeRuntimeEntryPointUnsupportedReason;

  @override
  String preview(EmbeddedNodeRuntimeConfig config) {
    return 'Data ${config.dataDir}  UDP ${config.udpHost}:${config.udpPort}';
  }

  @override
  Future<StartedEmbeddedRuntime> start(EmbeddedNodeRuntimeConfig config) async {
    if (!isSupported) {
      throw EmbeddedRuntimeUnavailable(
        unsupportedReason ?? 'Embedded node runtime is unavailable.',
      );
    }
    final runtime = await _startRuntime(config);
    return StartedEmbeddedRuntime.fromRuntime(runtime);
  }
}

class EmbeddedRuntimeUnavailable implements Exception {
  const EmbeddedRuntimeUnavailable(this.message);

  final String message;

  @override
  String toString() => message;
}

class EmbeddedRuntimeLifecycleState {
  const EmbeddedRuntimeLifecycleState({
    this.starting = false,
    this.stopping = false,
    this.runtime,
    this.error,
    this.actionCount = 0,
    this.lastAction,
  });

  final bool starting;
  final bool stopping;
  final StartedEmbeddedRuntime? runtime;
  final String? error;
  final int actionCount;
  final EmbeddedNodeAction? lastAction;

  bool get isRunning => runtime != null;
  bool get canStop => runtime != null && !stopping;

  EmbeddedRuntimeLifecycleState copyWith({
    bool? starting,
    bool? stopping,
    StartedEmbeddedRuntime? runtime,
    bool clearRuntime = false,
    String? error,
    bool clearError = false,
    int? actionCount,
    EmbeddedNodeAction? lastAction,
    bool clearLastAction = false,
  }) {
    return EmbeddedRuntimeLifecycleState(
      starting: starting ?? this.starting,
      stopping: stopping ?? this.stopping,
      runtime: clearRuntime ? null : runtime ?? this.runtime,
      error: clearError ? null : error ?? this.error,
      actionCount: actionCount ?? this.actionCount,
      lastAction: clearLastAction ? null : lastAction ?? this.lastAction,
    );
  }
}

final embeddedRuntimeStarterProvider = Provider<EmbeddedRuntimeStarter>((ref) {
  final serviceStarter = ref.watch(manyTierServiceStarterProvider);
  return NativeEmbeddedRuntimeStarter(
    defaultDataDir: serviceStarter.defaultDataDir,
  );
});

final embeddedVirtualNetworkFactoryProvider =
    Provider<EmbeddedVirtualNetworkFactory>((ref) {
      return const UnsupportedEmbeddedVirtualNetworkFactory();
    });

final embeddedRuntimeLifecycleProvider =
    StateNotifierProvider<
      EmbeddedRuntimeLifecycleController,
      EmbeddedRuntimeLifecycleState
    >((ref) {
      return EmbeddedRuntimeLifecycleController(ref);
    });

class EmbeddedRuntimeLifecycleController
    extends StateNotifier<EmbeddedRuntimeLifecycleState> {
  EmbeddedRuntimeLifecycleController(this._ref)
    : super(const EmbeddedRuntimeLifecycleState());

  final Ref _ref;
  StreamSubscription<EmbeddedNodeAction>? _actions;
  EmbeddedVirtualNetworkCoordinator? _virtualNetworks;

  EmbeddedRuntimeStarter get _starter =>
      _ref.read(embeddedRuntimeStarterProvider);

  String? unavailableReason() {
    if (!_starter.isSupported) {
      return _starter.unsupportedReason ??
          'Embedded node runtime is unavailable.';
    }
    return null;
  }

  EmbeddedNodeRuntimeConfig startConfig({
    String? dataDir,
    String udpHost = '0.0.0.0',
    int udpPort = 9993,
    String? libraryPath,
  }) {
    return EmbeddedNodeRuntimeConfig(
      dataDir: dataDir ?? _starter.defaultDataDir,
      udpHost: udpHost,
      udpPort: udpPort,
      libraryPath: libraryPath,
    );
  }

  String preview({EmbeddedNodeRuntimeConfig? config}) {
    return _starter.preview(config ?? startConfig());
  }

  Future<void> start({EmbeddedNodeRuntimeConfig? config}) async {
    if (state.starting || state.runtime != null) return;
    final reason = unavailableReason();
    if (reason != null) {
      state = state.copyWith(error: reason);
      return;
    }
    final startConfig = config ?? this.startConfig();
    state = state.copyWith(
      starting: true,
      clearError: true,
      actionCount: 0,
      clearLastAction: true,
    );
    try {
      final runtime = await _starter.start(startConfig);
      unawaited(_actions?.cancel());
      unawaited(_virtualNetworks?.close());
      _virtualNetworks = EmbeddedVirtualNetworkCoordinator(
        factory: _ref.read(embeddedVirtualNetworkFactoryProvider),
        packetSink: runtime.receiveVirtualPacket,
        nodeAddress: runtime.address,
        onError: (error, stackTrace) {
          if (!mounted) return;
          state = state.copyWith(error: '$error');
        },
      );
      _actions = runtime.actions.listen(
        _handleRuntimeAction,
        onError: (Object error, StackTrace stackTrace) {
          state = state.copyWith(error: '$error');
        },
      );
      state = EmbeddedRuntimeLifecycleState(runtime: runtime);
    } on EmbeddedRuntimeUnavailable catch (e) {
      state = EmbeddedRuntimeLifecycleState(error: e.message);
    } on Object catch (e) {
      state = EmbeddedRuntimeLifecycleState(error: '$e');
    }
  }

  Future<void> stop() async {
    final runtime = state.runtime;
    if (runtime == null || state.stopping) return;
    state = state.copyWith(stopping: true, clearError: true);
    try {
      unawaited(_actions?.cancel());
      _actions = null;
      final virtualNetworks = _virtualNetworks;
      _virtualNetworks = null;
      await virtualNetworks?.close();
      await runtime.close();
      state = const EmbeddedRuntimeLifecycleState();
    } on Object catch (e) {
      state = state.copyWith(stopping: false, error: '$e');
    }
  }

  void _handleRuntimeAction(EmbeddedNodeAction action) {
    state = state.copyWith(
      actionCount: state.actionCount + 1,
      lastAction: action,
      clearError: true,
    );
    final virtualNetworks = _virtualNetworks;
    if (virtualNetworks != null) {
      unawaited(_routeVirtualNetworkAction(virtualNetworks, action));
    }
  }

  Future<void> _routeVirtualNetworkAction(
    EmbeddedVirtualNetworkCoordinator virtualNetworks,
    EmbeddedNodeAction action,
  ) async {
    try {
      await virtualNetworks.handleAction(action);
    } on Object catch (e) {
      if (!mounted) return;
      state = state.copyWith(error: '$e');
    }
  }

  @override
  void dispose() {
    unawaited(_actions?.cancel());
    unawaited(_virtualNetworks?.close());
    final runtime = state.runtime;
    if (runtime != null) {
      unawaited(runtime.close());
    }
    super.dispose();
  }
}

String _hex(List<int> bytes) {
  const digits = '0123456789abcdef';
  return bytes
      .map((byte) => '${digits[(byte >> 4) & 0x0f]}${digits[byte & 0x0f]}')
      .join();
}
