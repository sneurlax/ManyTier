/// Riverpod state for the daemon connection: settings, token discovery,
/// and a 3-second polling loop over status + networks + peers.
library;

import 'dart:async';

import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../api/manytier_client.dart';
import '../api/token_discovery.dart';

const _prefsHostKey = 'manytier.connection.host';
const _prefsPortKey = 'manytier.connection.port';
const _prefsManualTokenKey = 'manytier.connection.manualToken';

/// Where and how to reach the local service.
class ConnectionSettings {
  const ConnectionSettings({
    this.host = '127.0.0.1',
    this.port = 9993,
    this.manualToken,
  });

  final String host;
  final int port;

  /// A user-pasted token that overrides the auto-discovered one.
  final String? manualToken;

  ConnectionSettings copyWith({String? host, int? port, String? manualToken}) {
    return ConnectionSettings(
      host: host ?? this.host,
      port: port ?? this.port,
      manualToken: manualToken ?? this.manualToken,
    );
  }
}

final connectionSettingsProvider =
    StateProvider<ConnectionSettings>((ref) => const ConnectionSettings());

/// Loads previously persisted connection settings, if any, and applies them
/// to [connectionSettingsProvider] exactly once. `app.dart` reads this via
/// `ref.watch` so the load kicks off at startup; the `AsyncValue` itself is
/// discarded; only the one-time side effect of updating
/// [connectionSettingsProvider] matters.
final connectionSettingsLoaderProvider = FutureProvider<void>((ref) async {
  final prefs = await SharedPreferences.getInstance();
  const defaults = ConnectionSettings();
  ref.read(connectionSettingsProvider.notifier).state = ConnectionSettings(
    host: prefs.getString(_prefsHostKey) ?? defaults.host,
    port: prefs.getInt(_prefsPortKey) ?? defaults.port,
    manualToken: prefs.getString(_prefsManualTokenKey),
  );
});

/// Persists every settings change so host/port/manual token survive restart.
final connectionSettingsPersistenceProvider = Provider<void>((ref) {
  ref.listen<ConnectionSettings>(connectionSettingsProvider,
      (previous, next) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_prefsHostKey, next.host);
    await prefs.setInt(_prefsPortKey, next.port);
    final manualToken = next.manualToken;
    if (manualToken == null || manualToken.isEmpty) {
      await prefs.remove(_prefsManualTokenKey);
    } else {
      await prefs.setString(_prefsManualTokenKey, manualToken);
    }
  }, fireImmediately: false);
});

/// Token read from `authtoken.secret` in one of the known data dirs
/// (always `null` on the web).
final discoveredTokenProvider =
    FutureProvider<String?>((ref) => discoverAuthToken());

/// The token sent: manual override first, else the discovered one.
final effectiveTokenProvider = Provider<String?>((ref) {
  final ConnectionSettings settings = ref.watch(connectionSettingsProvider);
  final String? manual = settings.manualToken;
  if (manual != null && manual.isNotEmpty) {
    return manual;
  }
  return ref.watch(discoveredTokenProvider).valueOrNull;
});

/// The client used by both the poller and one-shot actions (join/leave).
final manyTierClientProvider = Provider<ManyTierClient>((ref) {
  final ConnectionSettings settings = ref.watch(connectionSettingsProvider);
  final ManyTierClient client = ManyTierClient(
    host: settings.host,
    port: settings.port,
    token: ref.watch(effectiveTokenProvider),
  );
  ref.onDispose(client.close);
  return client;
});

/// Derived connection state.
sealed class DaemonConnection {
  const DaemonConnection();
}

/// Connection refused / socket error: the service is not running.
final class DaemonNotRunning extends DaemonConnection {
  const DaemonNotRunning();
}

/// The service is up but rejected our token (or we have none).
final class DaemonUnauthorized extends DaemonConnection {
  const DaemonUnauthorized();
}

/// Fully connected snapshot, refreshed every poll tick.
final class DaemonConnected extends DaemonConnection {
  const DaemonConnected({
    required this.status,
    required this.networks,
    required this.peers,
  });

  final ManyTierStatus status;
  final List<ManyTierNetwork> networks;
  final List<ManyTierPeer> peers;
}

/// Polls status + networks + peers every 3 seconds.
///
/// The timer lives as long as the provider; riverpod disposes it (via
/// [dispose]) whenever the settings/token change rebuild the provider or the
/// app shuts down, so a stale poller never keeps ticking.
class DaemonPoller extends StateNotifier<AsyncValue<DaemonConnection>> {
  DaemonPoller(this._client) : super(const AsyncValue.loading()) {
    refresh();
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
  }

  final ManyTierClient _client;
  Timer? _timer;
  bool _refreshing = false;

  Future<void> refresh() async {
    if (_refreshing) {
      return; // Skip overlapping ticks while a slow request is in flight.
    }
    _refreshing = true;
    try {
      final ManyTierStatus status = await _client.status();
      final List<ManyTierNetwork> networks = await _client.networks();
      final List<ManyTierPeer> peers = await _client.peers();
      if (!mounted) return;
      state = AsyncValue.data(
        DaemonConnected(status: status, networks: networks, peers: peers),
      );
    } on ServiceUnreachable {
      if (!mounted) return;
      state = const AsyncValue.data(DaemonNotRunning());
    } on Unauthorized {
      if (!mounted) return;
      state = const AsyncValue.data(DaemonUnauthorized());
    } on ManyTierException catch (e, st) {
      if (!mounted) return;
      state = AsyncValue.error(e, st);
    } finally {
      _refreshing = false;
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _timer = null;
    super.dispose();
  }
}

final daemonConnectionProvider =
    StateNotifierProvider<DaemonPoller, AsyncValue<DaemonConnection>>((ref) {
  return DaemonPoller(ref.watch(manyTierClientProvider));
});
