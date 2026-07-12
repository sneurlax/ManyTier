/// Conditional platform service starter factory.
library;

export 'service_process_stub.dart'
    if (dart.library.io) 'service_process_io.dart';
