/// Web implementation of token discovery: no filesystem, so nothing to probe.
library;

/// The `authtoken.secret` locations this platform can probe (none on web).
List<String> probedTokenPaths() => const <String>[];

/// Always `null` on the web: the token must be entered manually.
Future<String?> discoverAuthToken() async => null;
