/// Riverpod state for the daemon connection: saved connections, token
/// discovery, and a 3-second polling loop over status + networks + peers.
library;

import 'dart:async';
import 'dart:convert';

import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../api/manytier_client.dart';
import '../api/token_discovery.dart';

const _prefsConnectionsKey = 'manytier.connections';
const _prefsActiveIdKey = 'manytier.connections.activeId';

/// One saved host/port/token combo, identified by [id] so switching doesn't
/// depend on matching the tuple itself (a user may want two saved
/// connections that happen to share a host/port during migration).
class SavedConnection {
  const SavedConnection({
    required this.id,
    required this.label,
    this.host = '127.0.0.1',
    this.port = 9993,
    this.manualToken,
  });

  /// Stable identifier, generated once when the connection is added.
  final String id;

  /// User-facing name shown in the switcher (e.g. "Home NAS").
  final String label;

  final String host;
  final int port;

  /// A user-pasted token that overrides the auto-discovered one.
  final String? manualToken;

  SavedConnection copyWith({
    String? label,
    String? host,
    int? port,
    String? manualToken,
  }) {
    return SavedConnection(
      id: id,
      label: label ?? this.label,
      host: host ?? this.host,
      port: port ?? this.port,
      manualToken: manualToken ?? this.manualToken,
    );
  }

  Map<String, Object?> toJson() => <String, Object?>{
        'id': id,
        'label': label,
        'host': host,
        'port': port,
        'manualToken': manualToken,
      };

  factory SavedConnection.fromJson(Map<String, Object?> json) {
    return SavedConnection(
      id: json['id']! as String,
      label: json['label']! as String,
      host: json['host'] as String? ?? '127.0.0.1',
      port: json['port'] as int? ?? 9993,
      manualToken: json['manualToken'] as String?,
    );
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is SavedConnection &&
        other.id == id &&
        other.label == label &&
        other.host == host &&
        other.port == port &&
        other.manualToken == manualToken;
  }

  @override
  int get hashCode => Object.hash(id, label, host, port, manualToken);
}

/// The default connection created on first launch, when no saved
/// connections exist yet.
const defaultConnection = SavedConnection(id: 'default', label: 'Local');

/// All saved connections, in add order. Never empty in practice, since
/// [connectionsLoaderProvider] seeds [defaultConnection] on first launch,
/// but callers should not assume non-empty (e.g. a future "forget all").
final connectionsProvider =
    StateProvider<List<SavedConnection>>((ref) => const <SavedConnection>[]);

/// The id of the currently-active connection, or null before the loader
/// runs / when the list is empty.
final activeConnectionIdProvider = StateProvider<String?>((ref) => null);

/// The currently-active connection's full settings, or [defaultConnection]
/// as a last-resort fallback (e.g. the active id was forgotten elsewhere).
final connectionSettingsProvider = Provider<SavedConnection>((ref) {
  final List<SavedConnection> connections = ref.watch(connectionsProvider);
  final String? activeId = ref.watch(activeConnectionIdProvider);
  for (final SavedConnection c in connections) {
    if (c.id == activeId) return c;
  }
  return connections.isNotEmpty ? connections.first : defaultConnection;
});

/// Loads previously persisted connections, if any, and seeds
/// [connectionsProvider]/[activeConnectionIdProvider] exactly once.
/// `app.dart` reads this via `ref.watch` so the load kicks off at startup;
/// the `AsyncValue` itself is discarded; only the one-time side effect of
/// updating the providers above matters.
final connectionsLoaderProvider = FutureProvider<void>((ref) async {
  final prefs = await SharedPreferences.getInstance();
  final String? raw = prefs.getString(_prefsConnectionsKey);
  List<SavedConnection> connections = <SavedConnection>[];
  if (raw != null) {
    try {
      final List<Object?> decoded = jsonDecode(raw) as List<Object?>;
      connections = decoded
          .map((Object? e) => SavedConnection.fromJson(e! as Map<String, Object?>))
          .toList();
    } catch (_) {
      // Corrupt prefs value (e.g. from a future format): fall back to the
      // single default connection rather than crashing at startup.
      connections = <SavedConnection>[];
    }
  }
  if (connections.isEmpty) {
    connections = <SavedConnection>[defaultConnection];
  }
  ref.read(connectionsProvider.notifier).state = connections;
  final String? activeId = prefs.getString(_prefsActiveIdKey);
  final bool activeIsValid = connections.any((c) => c.id == activeId);
  ref.read(activeConnectionIdProvider.notifier).state =
      activeIsValid ? activeId : connections.first.id;
});

/// Persists the connection list and active id on every change.
final connectionsPersistenceProvider = Provider<void>((ref) {
  ref.listen<List<SavedConnection>>(connectionsProvider,
      (previous, next) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      _prefsConnectionsKey,
      jsonEncode(next.map((c) => c.toJson()).toList()),
    );
  }, fireImmediately: false);
  ref.listen<String?>(activeConnectionIdProvider, (previous, next) async {
    final prefs = await SharedPreferences.getInstance();
    if (next == null) {
      await prefs.remove(_prefsActiveIdKey);
    } else {
      await prefs.setString(_prefsActiveIdKey, next);
    }
  }, fireImmediately: false);
});

/// Mutations over the saved-connections list: add/switch/forget/update.
class ConnectionsController {
  ConnectionsController(this._ref);

  final Ref _ref;

  /// Adds a new saved connection and switches to it immediately.
  void add(SavedConnection connection) {
    final List<SavedConnection> next = <SavedConnection>[
      ..._ref.read(connectionsProvider),
      connection,
    ];
    _ref.read(connectionsProvider.notifier).state = next;
    _ref.read(activeConnectionIdProvider.notifier).state = connection.id;
  }

  /// Switches the active connection to [id]. No-op if [id] isn't saved.
  void switchTo(String id) {
    if (!_ref.read(connectionsProvider).any((c) => c.id == id)) return;
    _ref.read(activeConnectionIdProvider.notifier).state = id;
  }

  /// Removes the saved connection with [id]. If it was active, switches to
  /// the first remaining connection (or clears the active id if none are
  /// left, since [connectionSettingsProvider] falls back to [defaultConnection]
  /// in that case).
  void forget(String id) {
    final List<SavedConnection> remaining = _ref
        .read(connectionsProvider)
        .where((c) => c.id != id)
        .toList();
    _ref.read(connectionsProvider.notifier).state = remaining;
    if (_ref.read(activeConnectionIdProvider) == id) {
      _ref.read(activeConnectionIdProvider.notifier).state =
          remaining.isNotEmpty ? remaining.first.id : null;
    }
  }

  /// Replaces the saved connection matching `updated.id` in place (e.g. a
  /// manual-token update from the Unauthorized card).
  void update(SavedConnection updated) {
    final List<SavedConnection> next = <SavedConnection>[
      for (final SavedConnection c in _ref.read(connectionsProvider))
        if (c.id == updated.id) updated else c,
    ];
    _ref.read(connectionsProvider.notifier).state = next;
  }
}

final connectionsControllerProvider = Provider<ConnectionsController>((ref) {
  return ConnectionsController(ref);
});

/// Token read from `authtoken.secret` in one of the known data dirs
/// (always `null` on the web).
final discoveredTokenProvider =
    FutureProvider<String?>((ref) => discoverAuthToken());

/// The token sent: manual override first, else the discovered one.
final effectiveTokenProvider = Provider<String?>((ref) {
  final SavedConnection settings = ref.watch(connectionSettingsProvider);
  final String? manual = settings.manualToken;
  if (manual != null && manual.isNotEmpty) {
    return manual;
  }
  return ref.watch(discoveredTokenProvider).valueOrNull;
});

/// The client used by both the poller and one-shot actions (join/leave).
final manyTierClientProvider = Provider<ManyTierClient>((ref) {
  final SavedConnection settings = ref.watch(connectionSettingsProvider);
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
