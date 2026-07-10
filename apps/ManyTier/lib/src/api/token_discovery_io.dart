/// IO implementation of token discovery: probes the daemon's known data
/// directories for `authtoken.secret`.
library;

import 'dart:io';

/// The `authtoken.secret` locations probed, in order.
List<String> probedTokenPaths() {
  final String? home =
      Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
  return <String>[
    if (home != null && home.isNotEmpty) '$home/.manytier/authtoken.secret',
    '${Directory.current.path}/manytier-data/authtoken.secret',
    '/var/lib/manytier/authtoken.secret',
  ];
}

/// Reads the first readable `authtoken.secret`, or `null` if none is found.
Future<String?> discoverAuthToken() async {
  for (final String path in probedTokenPaths()) {
    try {
      final String token = (await File(path).readAsString()).trim();
      if (token.isNotEmpty) {
        return token;
      }
    } on FileSystemException {
      // Missing or unreadable: try the next candidate.
    }
  }
  return null;
}
