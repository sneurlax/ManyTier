import 'package:manytier_app/src/state/service_process.dart';

class FakeServiceStarter implements ManyTierServiceStarter {
  FakeServiceStarter({
    this.supported = true,
    this.defaultDir = '/tmp/manytier-test',
  });

  final bool supported;
  final String defaultDir;
  final List<ManyTierServiceStartRequest> starts =
      <ManyTierServiceStartRequest>[];
  int stops = 0;
  Object? nextStartError;

  @override
  bool get isSupported => supported;

  @override
  String? get unsupportedReason =>
      supported ? null : 'native process launch unavailable';

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
  Future<StartedManyTierService> start(
    ManyTierServiceStartRequest request,
  ) async {
    starts.add(request);
    final Object? error = nextStartError;
    if (error != null) {
      if (error is Exception) throw error;
      throw Exception('$error');
    }
    return StartedManyTierService(
      pid: 4242,
      command: commandPreview(request),
      stop: () async {
        stops++;
      },
    );
  }
}
