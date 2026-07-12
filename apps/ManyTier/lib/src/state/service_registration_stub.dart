/// Non-IO persistent service registrar: OS service management is unavailable.
library;

import 'service_process.dart';
import 'service_registration.dart';

ManyTierServiceRegistrar createPlatformServiceRegistrar() {
  return const UnsupportedManyTierServiceRegistrar();
}

class UnsupportedManyTierServiceRegistrar implements ManyTierServiceRegistrar {
  const UnsupportedManyTierServiceRegistrar();

  @override
  bool get isSupported => false;

  @override
  String get unsupportedReason =>
      'Persistent service registration is only available on macOS.';

  @override
  String get defaultDataDir => '~/.manytier';

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
    throw ServiceRegistrationUnavailable(unsupportedReason);
  }

  @override
  Future<ServiceRegistrationSnapshot> install(
    ManyTierServiceStartRequest request,
  ) async {
    throw ServiceRegistrationUnavailable(unsupportedReason);
  }

  @override
  Future<ServiceRegistrationSnapshot> uninstall() async {
    throw ServiceRegistrationUnavailable(unsupportedReason);
  }
}
