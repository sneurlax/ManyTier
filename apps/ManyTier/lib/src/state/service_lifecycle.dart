/// App-managed lifecycle helpers for the local `manytier service` process.
library;

import 'dart:async';

import 'package:hooks_riverpod/hooks_riverpod.dart';

import 'connection.dart';
import 'service_process.dart';
import 'service_process_platform.dart';

class ServiceLifecycleState {
  const ServiceLifecycleState({
    this.starting = false,
    this.stopping = false,
    this.startedService,
    this.error,
  });

  final bool starting;
  final bool stopping;
  final StartedManyTierService? startedService;
  final String? error;

  bool get canStop => startedService != null && !stopping;

  ServiceLifecycleState copyWith({
    bool? starting,
    bool? stopping,
    StartedManyTierService? startedService,
    bool clearStartedService = false,
    String? error,
    bool clearError = false,
  }) {
    return ServiceLifecycleState(
      starting: starting ?? this.starting,
      stopping: stopping ?? this.stopping,
      startedService: clearStartedService
          ? null
          : startedService ?? this.startedService,
      error: clearError ? null : error ?? this.error,
    );
  }
}

final manyTierServiceStarterProvider = Provider<ManyTierServiceStarter>(
  (ref) => createPlatformServiceStarter(),
);

final serviceLifecycleProvider =
    StateNotifierProvider<ServiceLifecycleController, ServiceLifecycleState>(
      (ref) => ServiceLifecycleController(ref),
    );

class ServiceLifecycleController extends StateNotifier<ServiceLifecycleState> {
  ServiceLifecycleController(this._ref) : super(const ServiceLifecycleState());

  final Ref _ref;

  ManyTierServiceStarter get _starter =>
      _ref.read(manyTierServiceStarterProvider);

  String commandPreview(SavedConnection connection) {
    return _starter.commandPreview(_requestFor(connection));
  }

  bool canStart(SavedConnection connection) {
    return _starter.isSupported && _isLocalHost(connection.host);
  }

  String? unavailableReason(SavedConnection connection) {
    if (!_starter.isSupported) return _starter.unsupportedReason;
    if (!_isLocalHost(connection.host)) {
      return 'The app can only start and stop a local daemon.';
    }
    return null;
  }

  Future<void> start(SavedConnection connection) async {
    if (state.starting || state.startedService != null) return;
    final String? reason = unavailableReason(connection);
    if (reason != null) {
      state = state.copyWith(error: reason);
      return;
    }
    state = state.copyWith(starting: true, clearError: true);
    try {
      final StartedManyTierService started = await _starter.start(
        _requestFor(connection),
      );
      state = ServiceLifecycleState(startedService: started);
    } on ServiceStartUnavailable catch (e) {
      state = ServiceLifecycleState(error: e.message);
    } on Object catch (e) {
      state = ServiceLifecycleState(error: '$e');
    }
  }

  Future<void> stop() async {
    final StartedManyTierService? service = state.startedService;
    if (service == null || state.stopping) return;
    state = state.copyWith(stopping: true, clearError: true);
    try {
      await service.stop();
      state = const ServiceLifecycleState();
    } on Object catch (e) {
      state = state.copyWith(stopping: false, error: '$e');
    }
  }

  ManyTierServiceStartRequest _requestFor(SavedConnection connection) {
    return ManyTierServiceStartRequest(
      apiPort: connection.port,
      udpPort: 9993,
      dataDir: _starter.defaultDataDir,
    );
  }

  bool _isLocalHost(String host) {
    final String normalized = host.trim().toLowerCase();
    return normalized == '127.0.0.1' ||
        normalized == 'localhost' ||
        normalized == '::1';
  }

  @override
  void dispose() {
    final StartedManyTierService? service = state.startedService;
    if (service != null) {
      unawaited(service.stop());
    }
    super.dispose();
  }
}
