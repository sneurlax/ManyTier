/// macOS LaunchAgent registration for `manytier service`.
library;

import 'dart:io';

import 'service_process.dart';
import 'service_registration.dart';

typedef ProcessRunner =
    Future<ProcessResult> Function(String executable, List<String> arguments);

ManyTierServiceRegistrar createPlatformServiceRegistrar() {
  return LaunchdManyTierServiceRegistrar();
}

class LaunchdManyTierServiceRegistrar implements ManyTierServiceRegistrar {
  LaunchdManyTierServiceRegistrar({
    Map<String, String>? environment,
    ProcessRunner? processRunner,
  }) : _environment = environment ?? Platform.environment,
       _runProcess = processRunner ?? Process.run;

  static const String _label = 'com.manymath.manytier.service';

  final Map<String, String> _environment;
  final ProcessRunner _runProcess;

  @override
  bool get isSupported => Platform.isMacOS && _home != null;

  @override
  String? get unsupportedReason {
    if (!Platform.isMacOS) {
      return 'Persistent service registration is only available on macOS.';
    }
    if (_home == null) {
      return 'Persistent service registration needs a HOME directory.';
    }
    return null;
  }

  @override
  String get defaultDataDir {
    final String? home = _home;
    if (home != null && home.isNotEmpty) return '$home/.manytier';
    return '${Directory.current.path}/manytier-data';
  }

  @override
  String commandPreview(ManyTierServiceStartRequest request) {
    return quoteCommand(<String>[
      _configuredExecutable ?? 'manytier',
      ...manyTierServiceArguments(request),
    ]);
  }

  @override
  Future<ServiceRegistrationSnapshot> inspect(
    ManyTierServiceStartRequest request,
  ) async {
    _throwIfUnsupported();
    final String plist = _plistPath;
    final bool installed = await File(plist).exists();
    return ServiceRegistrationSnapshot(
      installed: installed,
      loaded: installed && await _isLoaded(),
      label: _label,
      plistPath: plist,
      command: installed ? (await _commandFor(request)).commandLine : null,
    );
  }

  @override
  Future<ServiceRegistrationSnapshot> install(
    ManyTierServiceStartRequest request,
  ) async {
    _throwIfUnsupported();
    final ManyTierServiceCommand command = await _commandFor(request);
    await Directory(request.dataDir).create(recursive: true);
    await Directory(_launchAgentsDir).create(recursive: true);
    await Directory(_logsDir).create(recursive: true);
    await File(_plistPath).writeAsString(_plistFor(command));

    final String domain = await _launchdDomain();
    await _runLaunchctl(<String>[
      'bootout',
      domain,
      _plistPath,
    ], ignoreFailure: true);
    await _runLaunchctl(<String>['bootstrap', domain, _plistPath]);

    return inspect(request);
  }

  @override
  Future<ServiceRegistrationSnapshot> uninstall() async {
    _throwIfUnsupported();
    final String domain = await _launchdDomain();
    await _runLaunchctl(<String>[
      'bootout',
      domain,
      _plistPath,
    ], ignoreFailure: true);
    final File plist = File(_plistPath);
    if (await plist.exists()) {
      await plist.delete();
    }
    return ServiceRegistrationSnapshot(
      installed: false,
      loaded: false,
      label: _label,
      plistPath: _plistPath,
    );
  }

  String? get _home {
    final String? home = _environment['HOME'];
    return home == null || home.trim().isEmpty ? null : home.trim();
  }

  String get _launchAgentsDir => '${_home!}/Library/LaunchAgents';

  String get _logsDir => '${_home!}/Library/Logs/ManyTier';

  String get _plistPath => '$_launchAgentsDir/$_label.plist';

  String? get _configuredExecutable {
    final String? value = _environment['MANYTIER_BINARY'];
    return value == null || value.trim().isEmpty ? null : value.trim();
  }

  Future<ManyTierServiceCommand> _commandFor(
    ManyTierServiceStartRequest request,
  ) async {
    return ManyTierServiceCommand(
      executable: await _resolveExecutable(),
      arguments: manyTierServiceArguments(request),
    );
  }

  Future<String> _resolveExecutable() async {
    final String? configured = _configuredExecutable;
    if (configured != null) {
      final String? configuredOnPath = _findOnPath(configured);
      if (configuredOnPath != null) return configuredOnPath;
      return File(configured).absolute.path;
    }
    final String? path = _findOnPath('manytier');
    if (path != null) return path;
    throw const ServiceRegistrationUnavailable(
      'Could not find the manytier binary. Set MANYTIER_BINARY or add it to PATH before installing the service.',
    );
  }

  String? _findOnPath(String executable) {
    final String? path = _environment['PATH'];
    if (path == null || path.isEmpty) return null;
    final List<String> extensions = Platform.isWindows
        ? (_environment['PATHEXT'] ?? '.EXE;.BAT;.CMD')
              .split(';')
              .where((String extension) => extension.isNotEmpty)
              .toList()
        : <String>[''];
    for (final String dir in path.split(Platform.isWindows ? ';' : ':')) {
      if (dir.isEmpty) continue;
      for (final String extension in extensions) {
        final File candidate = File('$dir/$executable$extension');
        if (candidate.existsSync()) return candidate.path;
      }
    }
    return null;
  }

  Future<bool> _isLoaded() async {
    final String domain = await _launchdDomain();
    final ProcessResult result = await _runProcess('launchctl', <String>[
      'print',
      '$domain/$_label',
    ]);
    return result.exitCode == 0;
  }

  Future<String> _launchdDomain() async {
    final String? uid = _environment['UID'];
    if (uid != null && uid.trim().isNotEmpty) return 'gui/${uid.trim()}';
    final ProcessResult result = await _runProcess('id', const <String>['-u']);
    if (result.exitCode == 0) {
      return 'gui/${'${result.stdout}'.trim()}';
    }
    throw ServiceRegistrationUnavailable(
      'Could not determine the current user id for launchctl.',
    );
  }

  Future<void> _runLaunchctl(
    List<String> arguments, {
    bool ignoreFailure = false,
  }) async {
    final ProcessResult result = await _runProcess('launchctl', arguments);
    if (result.exitCode == 0 || ignoreFailure) return;
    final String details = <String>[
      '${result.stderr}'.trim(),
      '${result.stdout}'.trim(),
    ].where((String value) => value.isNotEmpty).join('\n');
    throw ServiceRegistrationUnavailable(
      details.isEmpty ? 'launchctl ${arguments.join(' ')} failed.' : details,
    );
  }

  String _plistFor(ManyTierServiceCommand command) {
    return '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$_label</string>
  <key>ProgramArguments</key>
  <array>
${command.parts.map((String part) => '    <string>${_escapeXml(part)}</string>').join('\n')}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${_escapeXml('$_logsDir/service.out.log')}</string>
  <key>StandardErrorPath</key>
  <string>${_escapeXml('$_logsDir/service.err.log')}</string>
</dict>
</plist>
''';
  }

  String _escapeXml(String value) {
    return value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&apos;');
  }

  void _throwIfUnsupported() {
    final String? reason = unsupportedReason;
    if (reason != null) throw ServiceRegistrationUnavailable(reason);
  }
}
