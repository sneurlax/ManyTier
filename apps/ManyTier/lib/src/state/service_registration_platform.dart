/// Conditional persistent service registrar factory.
library;

export 'service_registration_stub.dart'
    if (dart.library.io) 'service_registration_io.dart';
