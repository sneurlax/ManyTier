/// Riverpod state for orbited moons.
///
/// Unlike [daemonConnectionProvider] (status/networks/peers), moons are not
/// polled every 3 seconds: orbit membership only changes on explicit user
/// action (orbit/deorbit) or an out-of-band moon file drop, so a background
/// timer would just add load for data that almost never changes on its own.
/// Instead this loads once on first watch and refreshes on-demand after
/// every orbit/deorbit and via a manual refresh action.
library;

import 'package:hooks_riverpod/hooks_riverpod.dart';

import '../api/manytier_client.dart';
import 'connection.dart';

class MoonsNotifier extends StateNotifier<AsyncValue<List<Moon>>> {
  MoonsNotifier(this._client) : super(const AsyncValue.loading()) {
    refresh();
  }

  final ManyTierClient _client;

  Future<void> refresh() async {
    try {
      final List<Moon> moons = await _client.moons();
      if (!mounted) return;
      state = AsyncValue.data(moons);
    } on ManyTierException catch (e, st) {
      if (!mounted) return;
      state = AsyncValue.error(e, st);
    }
  }
}

final moonsProvider =
    StateNotifierProvider<MoonsNotifier, AsyncValue<List<Moon>>>((ref) {
  return MoonsNotifier(ref.watch(manyTierClientProvider));
});
