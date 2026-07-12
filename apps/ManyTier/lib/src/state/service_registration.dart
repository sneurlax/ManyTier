/// Persistent OS-service registration for `manytier service`.
library;

import 'package:hooks_riverpod/hooks_riverpod.dart';

import 'connection.dart';
import 'service_process.dart';
import 'service_registration_platform.dart';

class ServiceRegistrationSnapshot {
  const ServiceRegistrationSnapshot({
    required this.installed,
    required this.loaded,
    required this.label,
    required this.plistPath,
    this.command,
  });

  final bool installed;
  final bool loaded;
  final String label;
  final String plistPath;
  final String? command;
}

abstract interface class ManyTierServiceRegistrar {
  bool get isSupported;
  String? get unsupportedReason;
  String get defaultDataDir;

  String commandPreview(ManyTierServiceStartRequest request);
  Future<ServiceRegistrationSnapshot> inspect(
    ManyTierServiceStartRequest request,
  );
  Future<ServiceRegistrationSnapshot> install(
    ManyTierServiceStartRequest request,
  );
  Future<ServiceRegistrationSnapshot> uninstall();
}

class ServiceRegistrationUnavailable implements Exception {
  const ServiceRegistrationUnavailable(this.message);

  final String message;

  @override
  String toString() => message;
}

class ServiceRegistrationState {
  const ServiceRegistrationState({
    this.loading = false,
    this.installing = false,
    this.uninstalling = false,
    this.snapshot,
    this.error,
  });

  final bool loading;
  final bool installing;
  final bool uninstalling;
  final ServiceRegistrationSnapshot? snapshot;
  final String? error;

  bool get busy => loading || installing || uninstalling;
  bool get installed => snapshot?.installed ?? false;

  ServiceRegistrationState copyWith({
    bool? loading,
    bool? installing,
    bool? uninstalling,
    ServiceRegistrationSnapshot? snapshot,
    bool clearSnapshot = false,
    String? error,
    bool clearError = false,
  }) {
    return ServiceRegistrationState(
      loading: loading ?? this.loading,
      installing: installing ?? this.installing,
      uninstalling: uninstalling ?? this.uninstalling,
      snapshot: clearSnapshot ? null : snapshot ?? this.snapshot,
      error: clearError ? null : error ?? this.error,
    );
  }
}

final manyTierServiceRegistrarProvider = Provider<ManyTierServiceRegistrar>(
  (ref) => createPlatformServiceRegistrar(),
);

final serviceRegistrationProvider =
    StateNotifierProvider<
      ServiceRegistrationController,
      ServiceRegistrationState
    >((ref) => ServiceRegistrationController(ref));

class ServiceRegistrationController
    extends StateNotifier<ServiceRegistrationState> {
  ServiceRegistrationController(this._ref)
    : super(const ServiceRegistrationState());

  final Ref _ref;

  ManyTierServiceRegistrar get _registrar =>
      _ref.read(manyTierServiceRegistrarProvider);

  String commandPreview(SavedConnection connection) {
    return _registrar.commandPreview(_requestFor(connection));
  }

  String? unavailableReason(SavedConnection connection) {
    if (!_registrar.isSupported) return _registrar.unsupportedReason;
    if (!_isLocalHost(connection.host)) {
      return 'Only a local daemon can be registered to start at login.';
    }
    return null;
  }

  Future<void> refresh(SavedConnection connection) async {
    final String? reason = unavailableReason(connection);
    if (reason != null) {
      state = state.copyWith(clearSnapshot: true, clearError: true);
      return;
    }
    state = state.copyWith(loading: true, clearError: true);
    try {
      final ServiceRegistrationSnapshot snapshot = await _registrar.inspect(
        _requestFor(connection),
      );
      state = ServiceRegistrationState(snapshot: snapshot);
    } on ServiceRegistrationUnavailable catch (e) {
      state = ServiceRegistrationState(error: e.message);
    } on Object catch (e) {
      state = ServiceRegistrationState(error: '$e');
    }
  }

  Future<void> install(SavedConnection connection) async {
    if (state.busy) return;
    final String? reason = unavailableReason(connection);
    if (reason != null) {
      state = state.copyWith(error: reason);
      return;
    }
    state = state.copyWith(installing: true, clearError: true);
    try {
      final ServiceRegistrationSnapshot snapshot = await _registrar.install(
        _requestFor(connection),
      );
      state = ServiceRegistrationState(snapshot: snapshot);
    } on ServiceRegistrationUnavailable catch (e) {
      state = ServiceRegistrationState(error: e.message);
    } on Object catch (e) {
      state = ServiceRegistrationState(error: '$e');
    }
  }

  Future<void> uninstall() async {
    if (state.busy || !state.installed) return;
    state = state.copyWith(uninstalling: true, clearError: true);
    try {
      final ServiceRegistrationSnapshot snapshot = await _registrar.uninstall();
      state = ServiceRegistrationState(snapshot: snapshot);
    } on ServiceRegistrationUnavailable catch (e) {
      state = state.copyWith(uninstalling: false, error: e.message);
    } on Object catch (e) {
      state = state.copyWith(uninstalling: false, error: '$e');
    }
  }

  ManyTierServiceStartRequest _requestFor(SavedConnection connection) {
    return ManyTierServiceStartRequest(
      apiPort: connection.port,
      udpPort: 9993,
      dataDir: _registrar.defaultDataDir,
    );
  }

  bool _isLocalHost(String host) {
    final String normalized = host.trim().toLowerCase();
    return normalized == '127.0.0.1' ||
        normalized == 'localhost' ||
        normalized == '::1';
  }
}
