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
      assignedAddresses: (json['assignedAddresses'] as List<dynamic>? ??
              const <dynamic>[])
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
          .map((dynamic p) =>
              ManyTierPeerPath.fromJson(p as Map<String, dynamic>))
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

/// Matches a well-formed 16-hex network (or moon) id.
final RegExp networkIdPattern = RegExp(r'^[0-9a-fA-F]{16}$');

/// Small typed client over the daemon's REST surface.
///
/// All methods throw [ServiceUnreachable], [Unauthorized], or [ApiError].
// TODO(manytier): controller-mode endpoints (/controller/network CRUD and
// member authorization) are deferred to a later phase.
abstract class ManyTierClient {
  Future<ManyTierStatus> status();
  Future<List<ManyTierPeer>> peers();
  Future<List<ManyTierNetwork>> networks();
  Future<ManyTierNetwork> joinNetwork(String networkId);
  Future<void> leaveNetwork(String networkId);
  Future<List<Moon>> moons();
  Future<Moon> orbitMoon(String moonId);
  Future<void> deorbitMoon(String moonId);
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

  Uri _uri(String path) => Uri(scheme: 'http', host: host, port: port, path: path);

  Map<String, String> get _headers =>
      <String, String>{if (token != null) 'X-ZT1-Auth': token!};

  @override
  Future<ManyTierStatus> status() async {
    final http.Response res = await _get('/status');
    return _parse(res, (dynamic j) =>
        ManyTierStatus.fromJson(j as Map<String, dynamic>));
  }

  @override
  Future<List<ManyTierPeer>> peers() async {
    final http.Response res = await _get('/peer');
    return _parse(res, (dynamic j) => (j as List<dynamic>)
        .map((dynamic p) => ManyTierPeer.fromJson(p as Map<String, dynamic>))
        .toList());
  }

  @override
  Future<List<ManyTierNetwork>> networks() async {
    final http.Response res = await _get('/network');
    return _parse(res, (dynamic j) => (j as List<dynamic>)
        .map((dynamic n) =>
            ManyTierNetwork.fromJson(n as Map<String, dynamic>))
        .toList());
  }

  @override
  Future<ManyTierNetwork> joinNetwork(String networkId) async {
    _requireHexId(networkId);
    final http.Response res =
        await _run(() => _http.post(_uri('/network/$networkId'), headers: _headers));
    return _parse(res, (dynamic j) =>
        ManyTierNetwork.fromJson(j as Map<String, dynamic>));
  }

  @override
  Future<void> leaveNetwork(String networkId) async {
    _requireHexId(networkId);
    await _run(
        () => _http.delete(_uri('/network/$networkId'), headers: _headers));
  }

  @override
  Future<List<Moon>> moons() async {
    final http.Response res = await _get('/moon');
    return _parse(res, (dynamic j) => (j as List<dynamic>)
        .map((dynamic m) => Moon.fromJson(m as Map<String, dynamic>))
        .toList());
  }

  @override
  Future<Moon> orbitMoon(String moonId) async {
    _requireHexId(moonId);
    final http.Response res =
        await _run(() => _http.post(_uri('/moon/$moonId'), headers: _headers));
    return _parse(res, (dynamic j) => Moon.fromJson(j as Map<String, dynamic>));
  }

  @override
  Future<void> deorbitMoon(String moonId) async {
    _requireHexId(moonId);
    await _run(() => _http.delete(_uri('/moon/$moonId'), headers: _headers));
  }

  @override
  void close() => _http.close();

  void _requireHexId(String id) {
    if (!networkIdPattern.hasMatch(id)) {
      throw ArgumentError.value(id, 'id', 'must be a 16-character hex id');
    }
  }

  Future<http.Response> _get(String path) =>
      _run(() => _http.get(_uri(path), headers: _headers));

  Future<http.Response> _run(
      Future<http.Response> Function() request) async {
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
