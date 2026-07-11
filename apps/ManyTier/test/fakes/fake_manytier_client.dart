import 'package:manytier_app/src/api/manytier_client.dart';

/// In-memory [ManyTierClient] for widget tests: no HTTP, no daemon.
class FakeManyTierClient implements ManyTierClient {
  FakeManyTierClient({
    ManyTierStatus? status,
    List<ManyTierNetwork>? networks,
    List<ManyTierPeer>? peers,
    List<Moon>? moons,
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
       moons_ = moons ?? <Moon>[];

  ManyTierStatus status_;
  List<ManyTierNetwork> networks_;
  List<ManyTierPeer> peers_;
  List<Moon> moons_;

  /// If set, thrown by [orbitMoon]/[deorbitMoon] instead of mutating state.
  ManyTierException? nextActionError;

  int statusCalls = 0;
  int networksCalls = 0;
  int peersCalls = 0;
  int orbitCalls = 0;
  int deorbitCalls = 0;

  @override
  Future<ManyTierStatus> status() async {
    statusCalls++;
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
  void close() {}
}
