/// Typed HTTP client for the local `manytier service` control API.
///
/// The service speaks HTTP/1.1 JSON on 127.0.0.1:9993 (loopback only) and
/// authenticates via the `X-ZT1-Auth` header, whose 48-hex token lives in
/// `{data_dir}/authtoken.secret`. Response shapes mirror
/// `crates/zerotier-service/src/api/types.rs`.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

/// Base class for every failure mode of [ManyTierClient].
sealed class ManyTierException implements Exception {
  const ManyTierException(this.message);

  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// The service could not be reached at all (connection refused, socket
/// error). Usually means `manytier service` is not running.
final class ServiceUnreachable extends ManyTierException {
  const ServiceUnreachable(super.message);
}

/// The service answered 401: the auth token is missing or wrong.
final class Unauthorized extends ManyTierException {
  const Unauthorized([super.message = 'invalid or missing auth token']);
}

/// Any other non-2xx response, or a 2xx response whose body did not parse.
final class ApiError extends ManyTierException {
  const ApiError(this.status, super.message);

  final int status;

  @override
  String toString() => 'ApiError($status): $message';
}

/// GET /status.
class ManyTierStatus {
  const ManyTierStatus({
    required this.address,
    required this.version,
    required this.online,
    required this.publicIdentity,
  });

  factory ManyTierStatus.fromJson(Map<String, dynamic> json) {
    return ManyTierStatus(
      address: json['address'] as String,
      version: json['version'] as String,
      online: json['online'] as bool,
      publicIdentity: json['publicIdentity'] as String,
    );
  }

  final String address;
  final String version;
  final bool online;
  final String publicIdentity;
}

/// One element of GET /network, and the body of POST /network/:id.
class ManyTierNetwork {
  const ManyTierNetwork({
    required this.id,
    required this.name,
    required this.status,
    required this.assignedAddresses,
    required this.mac,
    required this.mtu,
  });

  factory ManyTierNetwork.fromJson(Map<String, dynamic> json) {
    return ManyTierNetwork(
      id: json['id'] as String,
      name: json['name'] as String? ?? '',
      status: json['status'] as String,
      assignedAddresses:
          (json['assignedAddresses'] as List<dynamic>? ?? const <dynamic>[])
              .cast<String>(),
      mac: json['mac'] as String? ?? '',
      mtu: (json['mtu'] as num?)?.toInt() ?? 0,
    );
  }

  final String id;
  final String name;

  /// "OK" or "REQUESTING_CONFIGURATION".
  final String status;
  final List<String> assignedAddresses;
  final String mac;
  final int mtu;
}

/// A physical path to a peer.
class ManyTierPeerPath {
  const ManyTierPeerPath({
    required this.address,
    required this.active,
    required this.lastReceive,
  });

  factory ManyTierPeerPath.fromJson(Map<String, dynamic> json) {
    return ManyTierPeerPath(
      address: json['address'] as String,
      active: json['active'] as bool? ?? false,
      lastReceive: (json['lastReceive'] as num?)?.toInt() ?? 0,
    );
  }

  final String address;
  final bool active;
  final int lastReceive;
}

/// One element of GET /peer.
class ManyTierPeer {
  const ManyTierPeer({
    required this.address,
    required this.paths,
    required this.latency,
    required this.role,
  });

  factory ManyTierPeer.fromJson(Map<String, dynamic> json) {
    return ManyTierPeer(
      address: json['address'] as String,
      paths: (json['paths'] as List<dynamic>? ?? const <dynamic>[])
          .map(
            (dynamic p) => ManyTierPeerPath.fromJson(p as Map<String, dynamic>),
          )
          .toList(),
      latency: (json['latency'] as num?)?.toInt() ?? -1,
      role: json['role'] as String? ?? 'LEAF',
    );
  }

  final String address;
  final List<ManyTierPeerPath> paths;
  final int latency;

  /// "LEAF" or "ROOT".
  final String role;
}

/// A root server inside a [Moon].
class MoonRoot {
  const MoonRoot({required this.address, required this.endpoints});

  factory MoonRoot.fromJson(Map<String, dynamic> json) {
    return MoonRoot(
      address: json['address'] as String,
      endpoints: (json['endpoints'] as List<dynamic>? ?? const <dynamic>[])
          .cast<String>(),
    );
  }

  final String address;
  final List<String> endpoints;
}

/// One element of GET /moon.
class Moon {
  const Moon({required this.id, required this.timestamp, required this.roots});

  factory Moon.fromJson(Map<String, dynamic> json) {
    return Moon(
      id: json['id'] as String,
      timestamp: (json['timestamp'] as num?)?.toInt() ?? 0,
      roots: (json['roots'] as List<dynamic>? ?? const <dynamic>[])
          .map((dynamic r) => MoonRoot.fromJson(r as Map<String, dynamic>))
          .toList(),
    );
  }

  final String id;
  final int timestamp;
  final List<MoonRoot> roots;
}

/// An IP auto-assignment range in a controller network config.
class ControllerIpPool {
  const ControllerIpPool({
    required this.ipRangeStart,
    required this.ipRangeEnd,
  });

  factory ControllerIpPool.fromJson(Map<String, dynamic> json) {
    return ControllerIpPool(
      ipRangeStart: json['ipRangeStart'] as String,
      ipRangeEnd: json['ipRangeEnd'] as String,
    );
  }

  final String ipRangeStart;
  final String ipRangeEnd;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'ipRangeStart': ipRangeStart,
    'ipRangeEnd': ipRangeEnd,
  };
}

/// A controller-managed route.
class ControllerRoute {
  const ControllerRoute({required this.target, required this.via});

  factory ControllerRoute.fromJson(Map<String, dynamic> json) {
    return ControllerRoute(
      target: json['target'] as String,
      via: json['via'] as String?,
    );
  }

  final String target;

  /// Gateway address, or null for routes owned directly by the network.
  final String? via;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'target': target,
    'via': via,
  };
}

/// A member tag assignment.
class ControllerTag {
  const ControllerTag({required this.id, required this.value});

  factory ControllerTag.fromJson(Map<String, dynamic> json) {
    return ControllerTag(
      id: (json['id'] as num).toInt(),
      value: (json['value'] as num).toInt(),
    );
  }

  final int id;
  final int value;

  Map<String, dynamic> toJson() => <String, dynamic>{'id': id, 'value': value};
}

/// GET/POST/DELETE /controller/network/:nwid response body.
class ControllerNetwork {
  const ControllerNetwork({
    required this.id,
    required this.name,
    required this.private,
    required this.creationTime,
    required this.revision,
    required this.multicastLimit,
    required this.mtu,
    required this.v4AssignMode,
    required this.v6AssignMode,
    required this.ipAssignmentPools,
    required this.enableBroadcast,
    required this.routes,
    required this.rules,
    required this.capabilities,
    required this.tags,
  });

  factory ControllerNetwork.fromJson(Map<String, dynamic> json) {
    return ControllerNetwork(
      id: json['id'] as String,
      name: json['name'] as String? ?? '',
      private: json['private'] as bool? ?? true,
      creationTime: (json['creationTime'] as num?)?.toInt() ?? 0,
      revision: (json['revision'] as num?)?.toInt() ?? 0,
      multicastLimit: (json['multicastLimit'] as num?)?.toInt() ?? 0,
      mtu: (json['mtu'] as num?)?.toInt() ?? 0,
      v4AssignMode: _jsonMap(json['v4AssignMode'] ?? const <String, dynamic>{}),
      v6AssignMode: _jsonMap(json['v6AssignMode'] ?? const <String, dynamic>{}),
      ipAssignmentPools:
          (json['ipAssignmentPools'] as List<dynamic>? ?? const <dynamic>[])
              .map(
                (dynamic p) =>
                    ControllerIpPool.fromJson(p as Map<String, dynamic>),
              )
              .toList(),
      enableBroadcast: json['enableBroadcast'] as bool? ?? false,
      routes: (json['routes'] as List<dynamic>? ?? const <dynamic>[])
          .map(
            (dynamic r) => ControllerRoute.fromJson(r as Map<String, dynamic>),
          )
          .toList(),
      rules: _jsonMapList(json['rules']),
      capabilities: _jsonMapList(json['capabilities']),
      tags: _jsonMapList(json['tags']),
    );
  }

  final String id;
  final String name;
  final bool private;
  final int creationTime;
  final int revision;
  final int multicastLimit;
  final int mtu;
  final Map<String, dynamic> v4AssignMode;
  final Map<String, dynamic> v6AssignMode;
  final List<ControllerIpPool> ipAssignmentPools;
  final bool enableBroadcast;
  final List<ControllerRoute> routes;

  /// Raw controller rule JSON. The daemon keeps this shape lossless.
  final List<Map<String, dynamic>> rules;

  /// Raw capability definition JSON.
  final List<Map<String, dynamic>> capabilities;

  /// Raw tag definition JSON.
  final List<Map<String, dynamic>> tags;
}

/// Partial body for POST /controller/network/:nwid.
class ControllerNetworkUpdate {
  const ControllerNetworkUpdate({
    this.name,
    this.private,
    this.multicastLimit,
    this.mtu,
    this.v4AssignMode,
    this.ipAssignmentPools,
    this.routes,
    this.enableBroadcast,
    this.rules,
    this.capabilities,
    this.tags,
  });

  final String? name;
  final bool? private;
  final int? multicastLimit;
  final int? mtu;
  final Map<String, dynamic>? v4AssignMode;
  final List<ControllerIpPool>? ipAssignmentPools;
  final List<ControllerRoute>? routes;
  final bool? enableBroadcast;
  final List<Map<String, dynamic>>? rules;
  final List<Map<String, dynamic>>? capabilities;
  final List<Map<String, dynamic>>? tags;

  Map<String, dynamic> toJson() => <String, dynamic>{
    if (name != null) 'name': name,
    if (private != null) 'private': private,
    if (multicastLimit != null) 'multicastLimit': multicastLimit,
    if (mtu != null) 'mtu': mtu,
    if (v4AssignMode != null) 'v4AssignMode': v4AssignMode,
    if (ipAssignmentPools != null)
      'ipAssignmentPools': ipAssignmentPools!
          .map((ControllerIpPool p) => p.toJson())
          .toList(),
    if (routes != null)
      'routes': routes!.map((ControllerRoute r) => r.toJson()).toList(),
    if (enableBroadcast != null) 'enableBroadcast': enableBroadcast,
    if (rules != null) 'rules': rules,
    if (capabilities != null) 'capabilities': capabilities,
    if (tags != null) 'tags': tags,
  };
}

/// GET/POST /controller/network/:nwid/member/:nodeId response body.
class ControllerMember {
  const ControllerMember({
    required this.id,
    required this.networkId,
    required this.authorized,
    required this.ipAssignments,
    required this.creationTime,
    required this.lastSeen,
    required this.name,
    required this.revision,
    required this.activeBridge,
    required this.noAutoAssignIps,
    required this.lastAuthorizedTime,
    required this.lastDeauthorizedTime,
    required this.vMajor,
    required this.vMinor,
    required this.vRev,
    required this.vProto,
    required this.capabilities,
    required this.tags,
  });

  factory ControllerMember.fromJson(Map<String, dynamic> json) {
    return ControllerMember(
      id: json['id'] as String,
      networkId: json['networkId'] as String,
      authorized: json['authorized'] as bool? ?? false,
      ipAssignments:
          (json['ipAssignments'] as List<dynamic>? ?? const <dynamic>[])
              .cast<String>(),
      creationTime: (json['creationTime'] as num?)?.toInt() ?? 0,
      lastSeen: (json['lastSeen'] as num?)?.toInt() ?? 0,
      name: json['name'] as String? ?? '',
      revision: (json['revision'] as num?)?.toInt() ?? 0,
      activeBridge: json['activeBridge'] as bool? ?? false,
      noAutoAssignIps: json['noAutoAssignIps'] as bool? ?? false,
      lastAuthorizedTime: (json['lastAuthorizedTime'] as num?)?.toInt() ?? 0,
      lastDeauthorizedTime:
          (json['lastDeauthorizedTime'] as num?)?.toInt() ?? 0,
      vMajor: (json['vMajor'] as num?)?.toInt() ?? -1,
      vMinor: (json['vMinor'] as num?)?.toInt() ?? -1,
      vRev: (json['vRev'] as num?)?.toInt() ?? -1,
      vProto: (json['vProto'] as num?)?.toInt() ?? -1,
      capabilities:
          (json['capabilities'] as List<dynamic>? ?? const <dynamic>[])
              .map((dynamic c) => (c as num).toInt())
              .toList(),
      tags: (json['tags'] as List<dynamic>? ?? const <dynamic>[])
          .map((dynamic t) => ControllerTag.fromJson(t as Map<String, dynamic>))
          .toList(),
    );
  }

  final String id;
  final String networkId;
  final bool authorized;
  final List<String> ipAssignments;
  final int creationTime;
  final int lastSeen;
  final String name;
  final int revision;
  final bool activeBridge;
  final bool noAutoAssignIps;
  final int lastAuthorizedTime;
  final int lastDeauthorizedTime;
  final int vMajor;
  final int vMinor;
  final int vRev;
  final int vProto;
  final List<int> capabilities;
  final List<ControllerTag> tags;
}

/// Partial body for POST /controller/network/:nwid/member/:nodeId.
class ControllerMemberUpdate {
  const ControllerMemberUpdate({
    this.authorized,
    this.ipAssignments,
    this.name,
    this.activeBridge,
    this.noAutoAssignIps,
    this.capabilities,
    this.tags,
  });

  final bool? authorized;
  final List<String>? ipAssignments;
  final String? name;
  final bool? activeBridge;
  final bool? noAutoAssignIps;
  final List<int>? capabilities;
  final List<ControllerTag>? tags;

  Map<String, dynamic> toJson() => <String, dynamic>{
    if (authorized != null) 'authorized': authorized,
    if (ipAssignments != null) 'ipAssignments': ipAssignments,
    if (name != null) 'name': name,
    if (activeBridge != null) 'activeBridge': activeBridge,
    if (noAutoAssignIps != null) 'noAutoAssignIps': noAutoAssignIps,
    if (capabilities != null) 'capabilities': capabilities,
    if (tags != null)
      'tags': tags!.map((ControllerTag t) => t.toJson()).toList(),
  };
}

Map<String, dynamic> _jsonMap(Object? value) =>
    Map<String, dynamic>.from(value as Map);

List<Map<String, dynamic>> _jsonMapList(Object? value) =>
    (value as List<dynamic>? ?? const <dynamic>[])
        .map((dynamic item) => _jsonMap(item))
        .toList();

/// Matches a well-formed 16-hex network (or moon) id.
final RegExp networkIdPattern = RegExp(r'^[0-9a-fA-F]{16}$');

/// Matches a well-formed 10-hex node/controller address.
final RegExp nodeAddressPattern = RegExp(r'^[0-9a-fA-F]{10}$');

/// Small typed client over the daemon's REST surface.
///
/// All methods throw [ServiceUnreachable], [Unauthorized], or [ApiError].
abstract class ManyTierClient {
  Future<ManyTierStatus> status();
  Future<List<ManyTierPeer>> peers();
  Future<List<ManyTierNetwork>> networks();
  Future<ManyTierNetwork> joinNetwork(String networkId);
  Future<void> leaveNetwork(String networkId);
  Future<List<Moon>> moons();
  Future<Moon> orbitMoon(String moonId);
  Future<void> deorbitMoon(String moonId);
  Future<List<String>> controllerNetworkIds();
  Future<ControllerNetwork> controllerNetwork(String networkId);
  Future<ControllerNetwork> createControllerNetwork(
    String controllerAddress, {
    ControllerNetworkUpdate update = const ControllerNetworkUpdate(),
  });
  Future<ControllerNetwork> updateControllerNetwork(
    String networkId,
    ControllerNetworkUpdate update,
  );
  Future<ControllerNetwork> deleteControllerNetwork(String networkId);
  Future<List<String>> controllerMemberIds(String networkId);
  Future<ControllerMember> controllerMember(String networkId, String memberId);
  Future<ControllerMember> updateControllerMember(
    String networkId,
    String memberId,
    ControllerMemberUpdate update,
  );
  Future<void> deleteControllerMember(String networkId, String memberId);
  void close();
}

/// [ManyTierClient] backed by real HTTP calls to a local `manytier service`.
class HttpManyTierClient implements ManyTierClient {
  HttpManyTierClient({
    http.Client? httpClient,
    this.host = '127.0.0.1',
    this.port = 9993,
    this.token,
  }) : _http = httpClient ?? http.Client();

  final http.Client _http;
  final String host;
  final int port;
  final String? token;

  Uri _uri(String path) =>
      Uri(scheme: 'http', host: host, port: port, path: path);

  Map<String, String> get _headers => <String, String>{
    if (token != null) 'X-ZT1-Auth': token!,
  };

  @override
  Future<ManyTierStatus> status() async {
    final http.Response res = await _get('/status');
    return _parse(
      res,
      (dynamic j) => ManyTierStatus.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<List<ManyTierPeer>> peers() async {
    final http.Response res = await _get('/peer');
    return _parse(
      res,
      (dynamic j) => (j as List<dynamic>)
          .map((dynamic p) => ManyTierPeer.fromJson(p as Map<String, dynamic>))
          .toList(),
    );
  }

  @override
  Future<List<ManyTierNetwork>> networks() async {
    final http.Response res = await _get('/network');
    return _parse(
      res,
      (dynamic j) => (j as List<dynamic>)
          .map(
            (dynamic n) => ManyTierNetwork.fromJson(n as Map<String, dynamic>),
          )
          .toList(),
    );
  }

  @override
  Future<ManyTierNetwork> joinNetwork(String networkId) async {
    _requireHexId(networkId);
    final http.Response res = await _run(
      () => _http.post(_uri('/network/$networkId'), headers: _headers),
    );
    return _parse(
      res,
      (dynamic j) => ManyTierNetwork.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<void> leaveNetwork(String networkId) async {
    _requireHexId(networkId);
    await _run(
      () => _http.delete(_uri('/network/$networkId'), headers: _headers),
    );
  }

  @override
  Future<List<Moon>> moons() async {
    final http.Response res = await _get('/moon');
    return _parse(
      res,
      (dynamic j) => (j as List<dynamic>)
          .map((dynamic m) => Moon.fromJson(m as Map<String, dynamic>))
          .toList(),
    );
  }

  @override
  Future<Moon> orbitMoon(String moonId) async {
    _requireHexId(moonId);
    final http.Response res = await _run(
      () => _http.post(_uri('/moon/$moonId'), headers: _headers),
    );
    return _parse(res, (dynamic j) => Moon.fromJson(j as Map<String, dynamic>));
  }

  @override
  Future<void> deorbitMoon(String moonId) async {
    _requireHexId(moonId);
    await _run(() => _http.delete(_uri('/moon/$moonId'), headers: _headers));
  }

  @override
  Future<List<String>> controllerNetworkIds() async {
    final http.Response res = await _get('/controller/network');
    return _parse(res, (dynamic j) => (j as List<dynamic>).cast<String>());
  }

  @override
  Future<ControllerNetwork> controllerNetwork(String networkId) async {
    _requireHexId(networkId);
    final http.Response res = await _get('/controller/network/$networkId');
    return _parse(
      res,
      (dynamic j) => ControllerNetwork.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<ControllerNetwork> createControllerNetwork(
    String controllerAddress, {
    ControllerNetworkUpdate update = const ControllerNetworkUpdate(),
  }) async {
    _requireNodeAddress(controllerAddress);
    final http.Response res = await _postJson(
      '/controller/network/${controllerAddress}______',
      update.toJson(),
    );
    return _parse(
      res,
      (dynamic j) => ControllerNetwork.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<ControllerNetwork> updateControllerNetwork(
    String networkId,
    ControllerNetworkUpdate update,
  ) async {
    _requireHexId(networkId);
    final http.Response res = await _postJson(
      '/controller/network/$networkId',
      update.toJson(),
    );
    return _parse(
      res,
      (dynamic j) => ControllerNetwork.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<ControllerNetwork> deleteControllerNetwork(String networkId) async {
    _requireHexId(networkId);
    final http.Response res = await _run(
      () => _http.delete(
        _uri('/controller/network/$networkId'),
        headers: _headers,
      ),
    );
    return _parse(
      res,
      (dynamic j) => ControllerNetwork.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<List<String>> controllerMemberIds(String networkId) async {
    _requireHexId(networkId);
    final http.Response res = await _get(
      '/controller/network/$networkId/member',
    );
    return _parse(res, (dynamic j) {
      final ids = Map<String, dynamic>.from(j as Map).keys.toList();
      ids.sort();
      return ids;
    });
  }

  @override
  Future<ControllerMember> controllerMember(
    String networkId,
    String memberId,
  ) async {
    _requireHexId(networkId);
    _requireNodeAddress(memberId);
    final http.Response res = await _get(
      '/controller/network/$networkId/member/$memberId',
    );
    return _parse(
      res,
      (dynamic j) => ControllerMember.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<ControllerMember> updateControllerMember(
    String networkId,
    String memberId,
    ControllerMemberUpdate update,
  ) async {
    _requireHexId(networkId);
    _requireNodeAddress(memberId);
    final http.Response res = await _postJson(
      '/controller/network/$networkId/member/$memberId',
      update.toJson(),
    );
    return _parse(
      res,
      (dynamic j) => ControllerMember.fromJson(j as Map<String, dynamic>),
    );
  }

  @override
  Future<void> deleteControllerMember(String networkId, String memberId) async {
    _requireHexId(networkId);
    _requireNodeAddress(memberId);
    await _run(
      () => _http.delete(
        _uri('/controller/network/$networkId/member/$memberId'),
        headers: _headers,
      ),
    );
  }

  @override
  void close() => _http.close();

  void _requireHexId(String id) {
    if (!networkIdPattern.hasMatch(id)) {
      throw ArgumentError.value(id, 'id', 'must be a 16-character hex id');
    }
  }

  void _requireNodeAddress(String address) {
    if (!nodeAddressPattern.hasMatch(address)) {
      throw ArgumentError.value(
        address,
        'address',
        'must be a 10-character hex node address',
      );
    }
  }

  Future<http.Response> _get(String path) =>
      _run(() => _http.get(_uri(path), headers: _headers));

  Future<http.Response> _postJson(String path, Map<String, dynamic> body) =>
      _run(
        () => _http.post(
          _uri(path),
          headers: <String, String>{
            ..._headers,
            'content-type': 'application/json',
          },
          body: jsonEncode(body),
        ),
      );

  Future<http.Response> _run(Future<http.Response> Function() request) async {
    final http.Response res;
    try {
      res = await request();
    } on http.ClientException catch (e) {
      // package:http normalizes socket-level failures (connection refused,
      // reset, DNS) to ClientException on every platform, including web.
      throw ServiceUnreachable(e.message);
    }
    if (res.statusCode == 401) {
      throw const Unauthorized();
    }
    if (res.statusCode < 200 || res.statusCode >= 300) {
      final String body = res.body.trim();
      throw ApiError(res.statusCode, body.isEmpty ? 'request failed' : body);
    }
    return res;
  }

  T _parse<T>(http.Response res, T Function(dynamic json) fromJson) {
    try {
      return fromJson(jsonDecode(res.body));
    } on FormatException catch (e) {
      throw ApiError(res.statusCode, 'malformed response: ${e.message}');
    } on TypeError catch (e) {
      throw ApiError(res.statusCode, 'malformed response: $e');
    }
  }
}
