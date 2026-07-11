import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:manytier_app/src/api/manytier_client.dart';

final String testToken = 'a' * 48;

ManyTierClient clientWith(MockClient mock, {String? token}) {
  return HttpManyTierClient(httpClient: mock, token: token ?? testToken);
}

Map<String, dynamic> controllerNetworkJson({
  String id = '8056c2e21c000001',
  String name = 'earth',
}) {
  return <String, dynamic>{
    'id': id,
    'name': name,
    'private': true,
    'creationTime': 1700000000000,
    'revision': 7,
    'multicastLimit': 32,
    'mtu': 2800,
    'v4AssignMode': <String, dynamic>{'zt': true},
    'v6AssignMode': <String, dynamic>{
      'zt': false,
      '6plane': false,
      'rfc4193': false,
    },
    'ipAssignmentPools': <Map<String, dynamic>>[
      <String, dynamic>{
        'ipRangeStart': '10.147.17.1',
        'ipRangeEnd': '10.147.17.254',
      },
    ],
    'enableBroadcast': true,
    'routes': <Map<String, dynamic>>[
      <String, dynamic>{'target': '10.147.17.0/24', 'via': null},
    ],
    'rules': <Map<String, dynamic>>[
      <String, dynamic>{
        'ruleType': 1,
        'type': 'ACTION_ACCEPT',
        'not': false,
        'or': false,
        'value': <int>[],
      },
    ],
    'capabilities': <Map<String, dynamic>>[
      <String, dynamic>{'id': 1, 'rules': <Map<String, dynamic>>[]},
    ],
    'tags': <Map<String, dynamic>>[
      <String, dynamic>{
        'id': 2,
        'name': 'role',
        'default': 0,
        'enums': <String, int>{'admin': 1},
      },
    ],
  };
}

Map<String, dynamic> controllerMemberJson({
  String id = 'abcdef0123',
  String networkId = '8056c2e21c000001',
  bool authorized = true,
}) {
  return <String, dynamic>{
    'id': id,
    'networkId': networkId,
    'authorized': authorized,
    'ipAssignments': <String>['10.147.17.2'],
    'creationTime': 1700000000000,
    'lastSeen': 1700000005000,
    'name': 'laptop',
    'revision': 4,
    'activeBridge': false,
    'noAutoAssignIps': true,
    'lastAuthorizedTime': 1700000006000,
    'lastDeauthorizedTime': 0,
    'vMajor': -1,
    'vMinor': -1,
    'vRev': -1,
    'vProto': -1,
    'capabilities': <int>[1],
    'tags': <Map<String, dynamic>>[
      <String, dynamic>{'id': 2, 'value': 1},
    ],
  };
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

    test('ControllerNetwork.fromJson parses controller config', () {
      final network = ControllerNetwork.fromJson(controllerNetworkJson());
      expect(network.id, '8056c2e21c000001');
      expect(network.name, 'earth');
      expect(network.private, isTrue);
      expect(network.creationTime, 1700000000000);
      expect(network.revision, 7);
      expect(network.multicastLimit, 32);
      expect(network.mtu, 2800);
      expect(network.v4AssignMode, <String, dynamic>{'zt': true});
      expect(network.v6AssignMode['6plane'], isFalse);
      expect(network.ipAssignmentPools.single.ipRangeStart, '10.147.17.1');
      expect(network.enableBroadcast, isTrue);
      expect(network.routes.single.target, '10.147.17.0/24');
      expect(network.routes.single.via, isNull);
      expect(network.rules.single['type'], 'ACTION_ACCEPT');
      expect(network.capabilities.single['id'], 1);
      expect(network.tags.single['name'], 'role');
    });

    test('ControllerNetworkUpdate.toJson omits unset fields', () {
      final body = ControllerNetworkUpdate(
        name: 'earth',
        private: false,
        multicastLimit: 64,
        mtu: 1400,
        v4AssignMode: const <String, dynamic>{'zt': false},
        ipAssignmentPools: const <ControllerIpPool>[
          ControllerIpPool(
            ipRangeStart: '10.147.18.1',
            ipRangeEnd: '10.147.18.254',
          ),
        ],
        routes: const <ControllerRoute>[
          ControllerRoute(target: '10.147.18.0/24', via: null),
        ],
        enableBroadcast: false,
      ).toJson();
      expect(body['name'], 'earth');
      expect(body['private'], isFalse);
      expect(body['multicastLimit'], 64);
      expect(body['mtu'], 1400);
      expect(body['v4AssignMode'], <String, dynamic>{'zt': false});
      expect(body['ipAssignmentPools'], <Map<String, dynamic>>[
        <String, dynamic>{
          'ipRangeStart': '10.147.18.1',
          'ipRangeEnd': '10.147.18.254',
        },
      ]);
      expect(body['routes'], <Map<String, dynamic>>[
        <String, dynamic>{'target': '10.147.18.0/24', 'via': null},
      ]);
      expect(body['enableBroadcast'], isFalse);
      expect(body.containsKey('rules'), isFalse);
    });

    test('ControllerMember.fromJson parses member details', () {
      final member = ControllerMember.fromJson(controllerMemberJson());
      expect(member.id, 'abcdef0123');
      expect(member.networkId, '8056c2e21c000001');
      expect(member.authorized, isTrue);
      expect(member.ipAssignments, <String>['10.147.17.2']);
      expect(member.name, 'laptop');
      expect(member.revision, 4);
      expect(member.noAutoAssignIps, isTrue);
      expect(member.lastAuthorizedTime, 1700000006000);
      expect(member.vMajor, -1);
      expect(member.capabilities, <int>[1]);
      expect(member.tags.single.id, 2);
      expect(member.tags.single.value, 1);
    });

    test('ControllerMemberUpdate.toJson serializes partial edits', () {
      final body = ControllerMemberUpdate(
        authorized: true,
        ipAssignments: const <String>['10.147.17.2'],
        name: 'laptop',
        activeBridge: true,
        noAutoAssignIps: false,
        capabilities: const <int>[1, 2],
        tags: const <ControllerTag>[ControllerTag(id: 2, value: 1)],
      ).toJson();
      expect(body, <String, dynamic>{
        'authorized': true,
        'ipAssignments': <String>['10.147.17.2'],
        'name': 'laptop',
        'activeBridge': true,
        'noAutoAssignIps': false,
        'capabilities': <int>[1, 2],
        'tags': <Map<String, dynamic>>[
          <String, dynamic>{'id': 2, 'value': 1},
        ],
      });
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
      expect(() => clientWith(mock).joinNetwork('nothex'), throwsArgumentError);
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

    test('controllerNetworkIds parses /controller/network list', () async {
      final mock = MockClient((http.Request request) async {
        expect(request.method, 'GET');
        expect(request.url.path, '/controller/network');
        return http.Response(jsonEncode(<String>['8056c2e21c000001']), 200);
      });
      final ids = await clientWith(mock).controllerNetworkIds();
      expect(ids, <String>['8056c2e21c000001']);
    });

    test('controllerNetwork gets one network', () async {
      final mock = MockClient((http.Request request) async {
        expect(request.method, 'GET');
        expect(request.url.path, '/controller/network/8056c2e21c000001');
        return http.Response(jsonEncode(controllerNetworkJson()), 200);
      });
      final network = await clientWith(
        mock,
      ).controllerNetwork('8056c2e21c000001');
      expect(network.name, 'earth');
    });

    test(
      'createControllerNetwork posts to controller-address placeholder',
      () async {
        final mock = MockClient((http.Request request) async {
          expect(request.method, 'POST');
          expect(request.url.path, '/controller/network/abcdef0123______');
          expect(request.headers['content-type'], 'application/json');
          expect(jsonDecode(request.body), <String, dynamic>{
            'name': 'earth',
            'private': true,
          });
          return http.Response(jsonEncode(controllerNetworkJson()), 200);
        });
        final network = await clientWith(mock).createControllerNetwork(
          'abcdef0123',
          update: const ControllerNetworkUpdate(name: 'earth', private: true),
        );
        expect(network.id, '8056c2e21c000001');
      },
    );

    test('updateControllerNetwork posts partial config body', () async {
      final mock = MockClient((http.Request request) async {
        expect(request.method, 'POST');
        expect(request.url.path, '/controller/network/8056c2e21c000001');
        expect(jsonDecode(request.body), <String, dynamic>{
          'name': 'mars',
          'ipAssignmentPools': <Map<String, dynamic>>[
            <String, dynamic>{
              'ipRangeStart': '10.147.18.1',
              'ipRangeEnd': '10.147.18.254',
            },
          ],
          'routes': <Map<String, dynamic>>[
            <String, dynamic>{'target': '10.147.18.0/24', 'via': null},
          ],
        });
        return http.Response(
          jsonEncode(controllerNetworkJson(name: 'mars')),
          200,
        );
      });
      final network = await clientWith(mock).updateControllerNetwork(
        '8056c2e21c000001',
        const ControllerNetworkUpdate(
          name: 'mars',
          ipAssignmentPools: <ControllerIpPool>[
            ControllerIpPool(
              ipRangeStart: '10.147.18.1',
              ipRangeEnd: '10.147.18.254',
            ),
          ],
          routes: <ControllerRoute>[
            ControllerRoute(target: '10.147.18.0/24', via: null),
          ],
        ),
      );
      expect(network.name, 'mars');
    });

    test(
      'deleteControllerNetwork issues DELETE and parses deleted network',
      () async {
        final mock = MockClient((http.Request request) async {
          expect(request.method, 'DELETE');
          expect(request.url.path, '/controller/network/8056c2e21c000001');
          return http.Response(jsonEncode(controllerNetworkJson()), 200);
        });
        final network = await clientWith(
          mock,
        ).deleteControllerNetwork('8056c2e21c000001');
        expect(network.id, '8056c2e21c000001');
      },
    );

    test(
      'controllerMemberIds parses member map keys in stable order',
      () async {
        final mock = MockClient((http.Request request) async {
          expect(request.method, 'GET');
          expect(
            request.url.path,
            '/controller/network/8056c2e21c000001/member',
          );
          return http.Response(
            jsonEncode(<String, int>{'f000000001': 1, 'abcdef0123': 1}),
            200,
          );
        });
        final ids = await clientWith(
          mock,
        ).controllerMemberIds('8056c2e21c000001');
        expect(ids, <String>['abcdef0123', 'f000000001']);
      },
    );

    test('controllerMember gets one member', () async {
      final mock = MockClient((http.Request request) async {
        expect(request.method, 'GET');
        expect(
          request.url.path,
          '/controller/network/8056c2e21c000001/member/abcdef0123',
        );
        return http.Response(jsonEncode(controllerMemberJson()), 200);
      });
      final member = await clientWith(
        mock,
      ).controllerMember('8056c2e21c000001', 'abcdef0123');
      expect(member.name, 'laptop');
    });

    test('updateControllerMember posts authorization and IP edits', () async {
      final mock = MockClient((http.Request request) async {
        expect(request.method, 'POST');
        expect(
          request.url.path,
          '/controller/network/8056c2e21c000001/member/abcdef0123',
        );
        expect(jsonDecode(request.body), <String, dynamic>{
          'authorized': true,
          'ipAssignments': <String>['10.147.17.2'],
        });
        return http.Response(jsonEncode(controllerMemberJson()), 200);
      });
      final member = await clientWith(mock).updateControllerMember(
        '8056c2e21c000001',
        'abcdef0123',
        const ControllerMemberUpdate(
          authorized: true,
          ipAssignments: <String>['10.147.17.2'],
        ),
      );
      expect(member.authorized, isTrue);
    });

    test(
      'deleteControllerMember issues DELETE and tolerates an empty body',
      () async {
        final mock = MockClient((http.Request request) async {
          expect(request.method, 'DELETE');
          expect(
            request.url.path,
            '/controller/network/8056c2e21c000001/member/abcdef0123',
          );
          return http.Response('', 200);
        });
        await clientWith(
          mock,
        ).deleteControllerMember('8056c2e21c000001', 'abcdef0123');
      },
    );

    test('controller methods reject malformed IDs before any request', () {
      final mock = MockClient((http.Request request) async {
        fail('no request expected');
      });
      final client = clientWith(mock);
      expect(
        () => client.createControllerNetwork('nothex'),
        throwsArgumentError,
      );
      expect(() => client.controllerNetwork('nothex'), throwsArgumentError);
      expect(
        () => client.controllerMember('8056c2e21c000001', 'nothex'),
        throwsArgumentError,
      );
    });

    test('401 maps to Unauthorized', () async {
      final mock = MockClient(
        (http.Request request) async => http.Response('unauthorized', 401),
      );
      expect(() => clientWith(mock).status(), throwsA(isA<Unauthorized>()));
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
        (http.Request request) async => http.Response('boom', 500),
      );
      expect(
        () => clientWith(mock).peers(),
        throwsA(
          isA<ApiError>()
              .having((ApiError e) => e.status, 'status', 500)
              .having((ApiError e) => e.message, 'message', 'boom'),
        ),
      );
    });

    test('malformed JSON maps to ApiError', () async {
      final mock = MockClient(
        (http.Request request) async => http.Response('not json {', 200),
      );
      expect(() => clientWith(mock).status(), throwsA(isA<ApiError>()));
    });

    test('wrong JSON shape maps to ApiError', () async {
      final mock = MockClient(
        (http.Request request) async => http.Response('{"nope": 1}', 200),
      );
      expect(() => clientWith(mock).status(), throwsA(isA<ApiError>()));
    });
  });
}
