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

class ManyTierServiceCommand {
  const ManyTierServiceCommand({
    required this.executable,
    required this.arguments,
  });

  final String executable;
  final List<String> arguments;

  List<String> get parts => <String>[executable, ...arguments];

  String get commandLine => quoteCommand(parts);
}

List<String> manyTierServiceArguments(ManyTierServiceStartRequest request) {
  return <String>[
    'service',
    '--data-dir',
    request.dataDir,
    '--api-port',
    '${request.apiPort}',
    '--udp-port',
    '${request.udpPort}',
    if (request.controllerMode) '--controller-mode',
  ];
}

String quoteCommand(List<String> parts) {
  return parts
      .map((String part) {
        if (!part.contains(RegExp(r'\s'))) return part;
        return '"${part.replaceAll('"', r'\"')}"';
      })
      .join(' ');
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
