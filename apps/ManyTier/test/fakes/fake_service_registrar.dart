import 'package:manytier_app/src/state/service_process.dart';
import 'package:manytier_app/src/state/service_registration.dart';

class FakeServiceRegistrar implements ManyTierServiceRegistrar {
  FakeServiceRegistrar({
    this.supported = true,
    this.defaultDir = '/tmp/manytier-test',
    this.installed = false,
    this.loaded = false,
  });

  final bool supported;
  final String defaultDir;
  bool installed;
  bool loaded;
  Object? nextInstallError;
  Object? nextUninstallError;
  final List<ManyTierServiceStartRequest> inspections =
      <ManyTierServiceStartRequest>[];
  final List<ManyTierServiceStartRequest> installs =
      <ManyTierServiceStartRequest>[];
  int uninstalls = 0;

  @override
  bool get isSupported => supported;

  @override
  String? get unsupportedReason =>
      supported ? null : 'launchd registration unavailable';

  @override
  String get defaultDataDir => defaultDir;

  @override
  String commandPreview(ManyTierServiceStartRequest request) {
    return quoteCommand(<String>[
      'manytier',
      ...manyTierServiceArguments(request),
    ]);
  }

  @override
  Future<ServiceRegistrationSnapshot> inspect(
    ManyTierServiceStartRequest request,
  ) async {
    inspections.add(request);
    return _snapshot(request);
  }

  @override
  Future<ServiceRegistrationSnapshot> install(
    ManyTierServiceStartRequest request,
  ) async {
    installs.add(request);
    final Object? error = nextInstallError;
    if (error != null) {
      if (error is Exception) throw error;
      throw Exception('$error');
    }
    installed = true;
    loaded = true;
    return _snapshot(request);
  }

  @override
  Future<ServiceRegistrationSnapshot> uninstall() async {
    uninstalls++;
    final Object? error = nextUninstallError;
    if (error != null) {
      if (error is Exception) throw error;
      throw Exception('$error');
    }
    installed = false;
    loaded = false;
    return _snapshot(
      ManyTierServiceStartRequest(
        apiPort: 9993,
        udpPort: 9993,
        dataDir: defaultDir,
      ),
    );
  }

  ServiceRegistrationSnapshot _snapshot(ManyTierServiceStartRequest request) {
    return ServiceRegistrationSnapshot(
      installed: installed,
      loaded: loaded,
      label: 'com.manymath.manytier.service',
      plistPath: '/tmp/LaunchAgents/com.manymath.manytier.service.plist',
      command: installed ? commandPreview(request) : null,
    );
  }
}
