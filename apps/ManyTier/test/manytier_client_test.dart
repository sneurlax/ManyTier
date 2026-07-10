import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:manytier_app/src/api/manytier_client.dart';

final String testToken = 'a' * 48;

ManyTierClient clientWith(MockClient mock, {String? token}) {
  return ManyTierClient(httpClient: mock, token: token ?? testToken);
}

void main() {
  group('model parsing', () {
    test('ManyTierStatus.fromJson', () {
      final status = ManyTierStatus.fromJson(<String, dynamic>{
        'address': 'abcdef0123',
        'version': '0.1.0',
        'online': true,
        'publicIdentity': 'abcdef0123:0:deadbeef',
      });
      expect(status.address, 'abcdef0123');
      expect(status.version, '0.1.0');
      expect(status.online, isTrue);
      expect(status.publicIdentity, 'abcdef0123:0:deadbeef');
    });

    test('ManyTierNetwork.fromJson', () {
      final network = ManyTierNetwork.fromJson(<String, dynamic>{
        'id': '8056c2e21c000001',
        'name': 'earth',
        'status': 'OK',
        'assignedAddresses': <String>['10.147.17.2/24'],
        'mac': '32:87:9a:aa:bb:cc',
        'mtu': 2800,
      });
      expect(network.id, '8056c2e21c000001');
      expect(network.name, 'earth');
      expect(network.status, 'OK');
      expect(network.assignedAddresses, <String>['10.147.17.2/24']);
      expect(network.mac, '32:87:9a:aa:bb:cc');
      expect(network.mtu, 2800);
    });

    test('ManyTierNetwork.fromJson tolerates missing optionals', () {
      final network = ManyTierNetwork.fromJson(<String, dynamic>{
        'id': '8056c2e21c000001',
        'status': 'REQUESTING_CONFIGURATION',
      });
      expect(network.name, isEmpty);
      expect(network.assignedAddresses, isEmpty);
      expect(network.mtu, 0);
    });

    test('ManyTierPeer.fromJson', () {
      final peer = ManyTierPeer.fromJson(<String, dynamic>{
        'address': '1122334455',
        'paths': <Map<String, dynamic>>[
          <String, dynamic>{
            'address': '192.0.2.1:9993',
            'active': true,
            'lastReceive': 123456,
          },
        ],
        'latency': 42,
        'role': 'ROOT',
      });
      expect(peer.address, '1122334455');
      expect(peer.paths, hasLength(1));
      expect(peer.paths.single.address, '192.0.2.1:9993');
      expect(peer.paths.single.active, isTrue);
      expect(peer.latency, 42);
      expect(peer.role, 'ROOT');
    });

    test('Moon.fromJson', () {
      final moon = Moon.fromJson(<String, dynamic>{
        'id': 'deadbeef00000001',
        'timestamp': 1700000000000,
        'roots': <Map<String, dynamic>>[
          <String, dynamic>{
            'address': '1122334455',
            'endpoints': <String>['203.0.113.1:9993'],
          },
        ],
      });
      expect(moon.id, 'deadbeef00000001');
      expect(moon.timestamp, 1700000000000);
      expect(moon.roots.single.endpoints, <String>['203.0.113.1:9993']);
    });
  });

  group('client', () {
    test('status sends X-ZT1-Auth and parses 200', () async {
      String? seenToken;
      final mock = MockClient((http.Request request) async {
        seenToken = request.headers['X-ZT1-Auth'];
        expect(request.url.path, '/status');
        return http.Response(
          jsonEncode(<String, dynamic>{
            'address': 'abcdef0123',
            'version': '0.1.0',
            'online': false,
            'publicIdentity': 'abcdef0123:0:00',
          }),
          200,
        );
      });
      final status = await clientWith(mock).status();
      expect(seenToken, 'a' * 48);
      expect(status.address, 'abcdef0123');
      expect(status.online, isFalse);
    });

    test('networks parses 200 list', () async {
      final mock = MockClient((http.Request request) async {
        expect(request.url.path, '/network');
        return http.Response(
          jsonEncode(<Map<String, dynamic>>[
            <String, dynamic>{
              'id': '8056c2e21c000001',
              'name': '',
              'status': 'OK',
              'assignedAddresses': <String>[],
              'mac': '32:87:9a:aa:bb:cc',
              'mtu': 2800,
            },
          ]),
          200,
        );
      });
      final networks = await clientWith(mock).networks();
      expect(networks, hasLength(1));
      expect(networks.single.id, '8056c2e21c000001');
    });

    test('join posts to /network/:id', () async {
      final mock = MockClient((http.Request request) async {
        expect(request.method, 'POST');
        expect(request.url.path, '/network/8056c2e21c000001');
        return http.Response(
          jsonEncode(<String, dynamic>{
            'id': '8056c2e21c000001',
            'name': '',
            'status': 'REQUESTING_CONFIGURATION',
            'assignedAddresses': <String>[],
            'mac': '32:87:9a:aa:bb:cc',
            'mtu': 2800,
          }),
          200,
        );
      });
      final network = await clientWith(mock).joinNetwork('8056c2e21c000001');
      expect(network.status, 'REQUESTING_CONFIGURATION');
    });

    test('join rejects a malformed id before any request', () {
      final mock = MockClient((http.Request request) async {
        fail('no request expected');
      });
      expect(
        () => clientWith(mock).joinNetwork('nothex'),
        throwsArgumentError,
      );
    });

    test('leave issues DELETE and tolerates an empty body', () async {
      String? method;
      final mock = MockClient((http.Request request) async {
        method = request.method;
        expect(request.url.path, '/network/8056c2e21c000001');
        return http.Response('', 200);
      });
      await clientWith(mock).leaveNetwork('8056c2e21c000001');
      expect(method, 'DELETE');
    });

    test('401 maps to Unauthorized', () async {
      final mock = MockClient(
          (http.Request request) async => http.Response('unauthorized', 401));
      expect(
        () => clientWith(mock).status(),
        throwsA(isA<Unauthorized>()),
      );
    });

    test('connection refused maps to ServiceUnreachable', () async {
      final mock = MockClient((http.Request request) async {
        throw http.ClientException('Connection refused', request.url);
      });
      expect(
        () => clientWith(mock).status(),
        throwsA(isA<ServiceUnreachable>()),
      );
    });

    test('non-2xx maps to ApiError with status and body', () async {
      final mock = MockClient(
          (http.Request request) async => http.Response('boom', 500));
      expect(
        () => clientWith(mock).peers(),
        throwsA(isA<ApiError>()
            .having((ApiError e) => e.status, 'status', 500)
            .having((ApiError e) => e.message, 'message', 'boom')),
      );
    });

    test('malformed JSON maps to ApiError', () async {
      final mock = MockClient(
          (http.Request request) async => http.Response('not json {', 200));
      expect(
        () => clientWith(mock).status(),
        throwsA(isA<ApiError>()),
      );
    });

    test('wrong JSON shape maps to ApiError', () async {
      final mock = MockClient(
          (http.Request request) async => http.Response('{"nope": 1}', 200));
      expect(
        () => clientWith(mock).status(),
        throwsA(isA<ApiError>()),
      );
    });
  });
}
