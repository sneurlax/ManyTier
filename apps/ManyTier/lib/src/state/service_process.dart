/// Platform service-process abstractions used by the lifecycle controller.
///
/// The Flutter app can run on platforms where `dart:io` is unavailable, so the
/// concrete process launcher lives behind a conditional import. Tests can also
/// inject a fake implementation without spawning a real daemon.
library;

class ManyTierServiceStartRequest {
  const ManyTierServiceStartRequest({
    required this.apiPort,
    required this.udpPort,
    required this.dataDir,
    this.controllerMode = false,
  });

  final int apiPort;
  final int udpPort;
  final String dataDir;
  final bool controllerMode;
}

class StartedManyTierService {
  const StartedManyTierService({
    required this.pid,
    required this.command,
    required this.stop,
  });

  final int pid;
  final String command;
  final Future<void> Function() stop;
}

abstract interface class ManyTierServiceStarter {
  bool get isSupported;
  String? get unsupportedReason;
  String get defaultDataDir;

  String commandPreview(ManyTierServiceStartRequest request);
  Future<StartedManyTierService> start(ManyTierServiceStartRequest request);
}

class ServiceStartUnavailable implements Exception {
  const ServiceStartUnavailable(this.message);

  final String message;

  @override
  String toString() => message;
}
