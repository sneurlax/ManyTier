import 'package:manytier_app/src/api/manytier_client.dart';

/// In-memory [ManyTierClient] for widget tests: no HTTP, no daemon.
class FakeManyTierClient implements ManyTierClient {
  FakeManyTierClient({
    ManyTierStatus? status,
    List<ManyTierNetwork>? networks,
    List<ManyTierPeer>? peers,
    List<Moon>? moons,
    List<ControllerNetwork>? controllerNetworks,
    Map<String, List<ControllerMember>>? controllerMembers,
    this.statusError,
  }) : status_ =
           status ??
           const ManyTierStatus(
             address: 'abcdef0123',
             version: '1.0.0',
             online: true,
             publicIdentity: 'abcdef0123:0:pub',
           ),
       networks_ = networks ?? <ManyTierNetwork>[],
       peers_ = peers ?? <ManyTierPeer>[],
       moons_ = moons ?? <Moon>[],
       controllerNetworks_ = controllerNetworks ?? <ControllerNetwork>[],
       controllerMembers_ =
           controllerMembers ?? <String, List<ControllerMember>>{};

  ManyTierStatus status_;
  List<ManyTierNetwork> networks_;
  List<ManyTierPeer> peers_;
  List<Moon> moons_;
  List<ControllerNetwork> controllerNetworks_;
  Map<String, List<ControllerMember>> controllerMembers_;
  ManyTierException? statusError;

  /// If set, thrown by [orbitMoon]/[deorbitMoon] instead of mutating state.
  ManyTierException? nextActionError;

  int statusCalls = 0;
  int networksCalls = 0;
  int peersCalls = 0;
  int orbitCalls = 0;
  int deorbitCalls = 0;
  int controllerNetworksCalls = 0;
  int controllerMembersCalls = 0;

  @override
  Future<ManyTierStatus> status() async {
    statusCalls++;
    final ManyTierException? error = statusError;
    if (error != null) {
      throw error;
    }
    return status_;
  }

  @override
  Future<List<ManyTierPeer>> peers() async {
    peersCalls++;
    return peers_;
  }

  @override
  Future<List<ManyTierNetwork>> networks() async {
    networksCalls++;
    return networks_;
  }

  @override
  Future<ManyTierNetwork> joinNetwork(String networkId) async {
    final ManyTierNetwork network = ManyTierNetwork(
      id: networkId,
      name: '',
      status: 'OK',
      assignedAddresses: const <String>[],
      mac: '',
      mtu: 2800,
    );
    networks_ = <ManyTierNetwork>[...networks_, network];
    return network;
  }

  @override
  Future<void> leaveNetwork(String networkId) async {
    networks_ = networks_
        .where((ManyTierNetwork n) => n.id != networkId)
        .toList();
  }

  @override
  Future<List<Moon>> moons() async => moons_;

  @override
  Future<Moon> orbitMoon(String moonId) async {
    orbitCalls++;
    final ManyTierException? error = nextActionError;
    if (error != null) {
      nextActionError = null;
      throw error;
    }
    final Moon moon = Moon(id: moonId, timestamp: 0, roots: const <MoonRoot>[]);
    moons_ = <Moon>[...moons_, moon];
    return moon;
  }

  @override
  Future<void> deorbitMoon(String moonId) async {
    deorbitCalls++;
    final ManyTierException? error = nextActionError;
    if (error != null) {
      nextActionError = null;
      throw error;
    }
    moons_ = moons_.where((Moon m) => m.id != moonId).toList();
  }

  @override
  Future<List<String>> controllerNetworkIds() async {
    controllerNetworksCalls++;
    return controllerNetworks_
        .map((ControllerNetwork network) => network.id)
        .toList();
  }

  @override
  Future<ControllerNetwork> controllerNetwork(String networkId) async {
    return _findControllerNetwork(networkId);
  }

  @override
  Future<ControllerNetwork> createControllerNetwork(
    String controllerAddress, {
    ControllerNetworkUpdate update = const ControllerNetworkUpdate(),
  }) async {
    final int suffix =
        controllerNetworks_
            .where((ControllerNetwork n) => n.id.startsWith(controllerAddress))
            .length +
        1;
    final String networkId =
        '$controllerAddress${suffix.toRadixString(16).padLeft(6, '0')}';
    final ControllerNetwork network = _applyControllerNetworkUpdate(
      _newControllerNetwork(networkId),
      update,
    );
    controllerNetworks_ = <ControllerNetwork>[...controllerNetworks_, network];
    return network;
  }

  @override
  Future<ControllerNetwork> updateControllerNetwork(
    String networkId,
    ControllerNetworkUpdate update,
  ) async {
    final int index = controllerNetworks_.indexWhere(
      (ControllerNetwork n) => n.id == networkId,
    );
    if (index < 0) {
      throw const ApiError(404, 'network not found');
    }
    final ControllerNetwork network = _applyControllerNetworkUpdate(
      controllerNetworks_[index],
      update,
    );
    controllerNetworks_ = <ControllerNetwork>[
      ...controllerNetworks_.take(index),
      network,
      ...controllerNetworks_.skip(index + 1),
    ];
    return network;
  }

  @override
  Future<ControllerNetwork> deleteControllerNetwork(String networkId) async {
    final ControllerNetwork network = _findControllerNetwork(networkId);
    controllerNetworks_ = controllerNetworks_
        .where((ControllerNetwork n) => n.id != networkId)
        .toList();
    controllerMembers_.remove(networkId);
    return network;
  }

  @override
  Future<List<String>> controllerMemberIds(String networkId) async {
    controllerMembersCalls++;
    final List<String> ids =
        (controllerMembers_[networkId] ?? <ControllerMember>[])
            .map((ControllerMember member) => member.id)
            .toList();
    ids.sort();
    return ids;
  }

  @override
  Future<ControllerMember> controllerMember(
    String networkId,
    String memberId,
  ) async {
    return _findControllerMember(networkId, memberId);
  }

  @override
  Future<ControllerMember> updateControllerMember(
    String networkId,
    String memberId,
    ControllerMemberUpdate update,
  ) async {
    final List<ControllerMember> members =
        controllerMembers_[networkId] ?? <ControllerMember>[];
    final int index = members.indexWhere(
      (ControllerMember member) => member.id == memberId,
    );
    final ControllerMember existing = index < 0
        ? _newControllerMember(networkId, memberId)
        : members[index];
    final ControllerMember updated = _applyControllerMemberUpdate(
      existing,
      update,
    );
    controllerMembers_[networkId] = <ControllerMember>[
      ...members.take(index < 0 ? members.length : index),
      updated,
      if (index >= 0) ...members.skip(index + 1),
    ];
    return updated;
  }

  @override
  Future<void> deleteControllerMember(String networkId, String memberId) async {
    controllerMembers_[networkId] =
        (controllerMembers_[networkId] ?? <ControllerMember>[])
            .where((ControllerMember member) => member.id != memberId)
            .toList();
  }

  @override
  void close() {}

  ControllerNetwork _findControllerNetwork(String networkId) {
    return controllerNetworks_.firstWhere(
      (ControllerNetwork network) => network.id == networkId,
      orElse: () => throw const ApiError(404, 'network not found'),
    );
  }

  ControllerMember _findControllerMember(String networkId, String memberId) {
    return (controllerMembers_[networkId] ?? <ControllerMember>[]).firstWhere(
      (ControllerMember member) => member.id == memberId,
      orElse: () => throw const ApiError(404, 'member not found'),
    );
  }
}

ControllerNetwork _newControllerNetwork(String networkId) {
  return ControllerNetwork(
    id: networkId,
    name: '',
    private: true,
    creationTime: 0,
    revision: 0,
    multicastLimit: 32,
    mtu: 2800,
    v4AssignMode: const <String, dynamic>{'zt': true},
    v6AssignMode: const <String, dynamic>{
      'zt': false,
      '6plane': false,
      'rfc4193': false,
    },
    ipAssignmentPools: const <ControllerIpPool>[],
    enableBroadcast: true,
    routes: const <ControllerRoute>[],
    rules: const <Map<String, dynamic>>[],
    capabilities: const <Map<String, dynamic>>[],
    tags: const <Map<String, dynamic>>[],
  );
}

ControllerNetwork _applyControllerNetworkUpdate(
  ControllerNetwork network,
  ControllerNetworkUpdate update,
) {
  return ControllerNetwork(
    id: network.id,
    name: update.name ?? network.name,
    private: update.private ?? network.private,
    creationTime: network.creationTime,
    revision: network.revision + 1,
    multicastLimit: update.multicastLimit ?? network.multicastLimit,
    mtu: update.mtu ?? network.mtu,
    v4AssignMode: update.v4AssignMode ?? network.v4AssignMode,
    v6AssignMode: network.v6AssignMode,
    ipAssignmentPools: update.ipAssignmentPools ?? network.ipAssignmentPools,
    enableBroadcast: update.enableBroadcast ?? network.enableBroadcast,
    routes: update.routes ?? network.routes,
    rules: update.rules ?? network.rules,
    capabilities: update.capabilities ?? network.capabilities,
    tags: update.tags ?? network.tags,
  );
}

ControllerMember _newControllerMember(String networkId, String memberId) {
  return ControllerMember(
    id: memberId,
    networkId: networkId,
    authorized: false,
    ipAssignments: const <String>[],
    creationTime: 0,
    lastSeen: 0,
    name: '',
    revision: 0,
    activeBridge: false,
    noAutoAssignIps: false,
    lastAuthorizedTime: 0,
    lastDeauthorizedTime: 0,
    vMajor: -1,
    vMinor: -1,
    vRev: -1,
    vProto: -1,
    capabilities: const <int>[],
    tags: const <ControllerTag>[],
  );
}

ControllerMember _applyControllerMemberUpdate(
  ControllerMember member,
  ControllerMemberUpdate update,
) {
  return ControllerMember(
    id: member.id,
    networkId: member.networkId,
    authorized: update.authorized ?? member.authorized,
    ipAssignments: update.ipAssignments ?? member.ipAssignments,
    creationTime: member.creationTime,
    lastSeen: member.lastSeen,
    name: update.name ?? member.name,
    revision: member.revision + 1,
    activeBridge: update.activeBridge ?? member.activeBridge,
    noAutoAssignIps: update.noAutoAssignIps ?? member.noAutoAssignIps,
    lastAuthorizedTime: member.lastAuthorizedTime,
    lastDeauthorizedTime: member.lastDeauthorizedTime,
    vMajor: member.vMajor,
    vMinor: member.vMinor,
    vRev: member.vRev,
    vProto: member.vProto,
    capabilities: update.capabilities ?? member.capabilities,
    tags: update.tags ?? member.tags,
  );
}
