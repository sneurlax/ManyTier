/// Native process starter for `manytier service`.
library;

import 'dart:async';
import 'dart:io';

import 'service_process.dart';

ManyTierServiceStarter createPlatformServiceStarter() {
  return IoManyTierServiceStarter();
}

class IoManyTierServiceStarter implements ManyTierServiceStarter {
  IoManyTierServiceStarter({Map<String, String>? environment})
    : _environment = environment ?? Platform.environment;

  final Map<String, String> _environment;

  @override
  bool get isSupported => true;

  @override
  String? get unsupportedReason => null;

  @override
  String get defaultDataDir {
    final String? home = _environment['HOME'] ?? _environment['USERPROFILE'];
    if (home != null && home.isNotEmpty) return '$home/.manytier';
    return '${Directory.current.path}/manytier-data';
  }

  @override
  String commandPreview(ManyTierServiceStartRequest request) {
    return _quoteCommand(<String>[
      _configuredExecutable ?? 'manytier',
      'service',
      '--data-dir',
      request.dataDir,
      '--api-port',
      '${request.apiPort}',
      '--udp-port',
      '${request.udpPort}',
      if (request.controllerMode) '--controller-mode',
    ]);
  }

  @override
  Future<StartedManyTierService> start(
    ManyTierServiceStartRequest request,
  ) async {
    final String executable = await _resolveExecutable();
    await Directory(request.dataDir).create(recursive: true);
    final List<String> args = <String>[
      'service',
      '--data-dir',
      request.dataDir,
      '--api-port',
      '${request.apiPort}',
      '--udp-port',
      '${request.udpPort}',
      if (request.controllerMode) '--controller-mode',
    ];
    final Process process = await Process.start(
      executable,
      args,
      mode: ProcessStartMode.normal,
    );
    unawaited(process.stdout.drain<void>());
    unawaited(process.stderr.drain<void>());
    return StartedManyTierService(
      pid: process.pid,
      command: _quoteCommand(<String>[executable, ...args]),
      stop: () async {
        process.kill();
        try {
          await process.exitCode.timeout(const Duration(seconds: 2));
        } on TimeoutException {
          process.kill(ProcessSignal.sigkill);
        }
      },
    );
  }

  String? get _configuredExecutable {
    final String? value = _environment['MANYTIER_BINARY'];
    return value == null || value.trim().isEmpty ? null : value.trim();
  }

  Future<String> _resolveExecutable() async {
    final String? configured = _configuredExecutable;
    if (configured != null) return configured;
    final String? path = _findOnPath('manytier');
    if (path != null) return path;
    throw const ServiceStartUnavailable(
      'Could not find the manytier binary. Set MANYTIER_BINARY or add it to PATH.',
    );
  }

  String? _findOnPath(String executable) {
    final String? path = _environment['PATH'];
    if (path == null || path.isEmpty) return null;
    final String separator = Platform.isWindows ? ';' : ':';
    final List<String> extensions = Platform.isWindows
        ? (_environment['PATHEXT'] ?? '.EXE;.BAT;.CMD')
              .split(';')
              .where((String extension) => extension.isNotEmpty)
              .toList()
        : <String>[''];
    for (final String dir in path.split(separator)) {
      if (dir.isEmpty) continue;
      for (final String extension in extensions) {
        final File candidate = File('$dir/$executable$extension');
        if (candidate.existsSync()) return candidate.path;
      }
    }
    return null;
  }

  String _quoteCommand(List<String> parts) {
    return parts
        .map((String part) {
          if (!part.contains(RegExp(r'\s'))) return part;
          return '"${part.replaceAll('"', r'\"')}"';
        })
        .join(' ');
  }
}
