/// Non-IO service starter: process management is unavailable.
library;

import 'service_process.dart';

ManyTierServiceStarter createPlatformServiceStarter() {
  return const UnsupportedManyTierServiceStarter();
}

class UnsupportedManyTierServiceStarter implements ManyTierServiceStarter {
  const UnsupportedManyTierServiceStarter();

  @override
  bool get isSupported => false;

  @override
  String get unsupportedReason =>
      'Starting the daemon from the app is only available on native platforms.';

  @override
  String get defaultDataDir => '~/.manytier';

  @override
  String commandPreview(ManyTierServiceStartRequest request) {
    return 'manytier service --data-dir ${request.dataDir} '
        '--api-port ${request.apiPort} --udp-port ${request.udpPort}';
  }

  @override
  Future<StartedManyTierService> start(
    ManyTierServiceStartRequest request,
  ) async {
    throw ServiceStartUnavailable(unsupportedReason);
  }
}
