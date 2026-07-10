/// Auth-token discovery for the local `manytier service`.
///
/// On IO platforms this probes the daemon's known data directories for
/// `authtoken.secret`; on the web the filesystem is unavailable, so discovery
/// always fails and users must paste the token manually.
library;

export 'token_discovery_stub.dart'
    if (dart.library.io) 'token_discovery_io.dart';
