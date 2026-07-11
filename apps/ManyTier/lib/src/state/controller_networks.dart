/// Riverpod state for controller-mode networks and members.
///
/// Controller data changes only through explicit operator actions in this UI,
/// so this provider mirrors [moonsProvider]: load once, then refresh after
/// create/update/delete operations instead of polling.
library;

import 'package:hooks_riverpod/hooks_riverpod.dart';

import '../api/manytier_client.dart';
import 'connection.dart';

class ControllerNetworkDetail {
  const ControllerNetworkDetail({required this.network, required this.members});

  final ControllerNetwork network;
  final List<ControllerMember> members;
}

class ControllerNetworksNotifier
    extends StateNotifier<AsyncValue<List<ControllerNetworkDetail>>> {
  ControllerNetworksNotifier(this._client) : super(const AsyncValue.loading()) {
    refresh();
  }

  final ManyTierClient _client;

  Future<void> refresh() async {
    try {
      final List<String> networkIds = await _client.controllerNetworkIds();
      final List<ControllerNetworkDetail> details = <ControllerNetworkDetail>[];
      for (final String networkId in networkIds) {
        final ControllerNetwork network = await _client.controllerNetwork(
          networkId,
        );
        final List<String> memberIds = await _client.controllerMemberIds(
          networkId,
        );
        final List<ControllerMember> members = <ControllerMember>[];
        for (final String memberId in memberIds) {
          members.add(await _client.controllerMember(networkId, memberId));
        }
        details.add(
          ControllerNetworkDetail(network: network, members: members),
        );
      }
      if (!mounted) return;
      state = AsyncValue.data(details);
    } on ManyTierException catch (e, st) {
      if (!mounted) return;
      state = AsyncValue.error(e, st);
    }
  }
}

final controllerNetworksProvider =
    StateNotifierProvider<
      ControllerNetworksNotifier,
      AsyncValue<List<ControllerNetworkDetail>>
    >((ref) => ControllerNetworksNotifier(ref.watch(manyTierClientProvider)));
