import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manytier_app/src/api/manytier_client.dart';
import 'package:manytier_app/src/state/connection.dart';
import 'package:manytier_app/src/state/service_lifecycle.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'fakes/fake_manytier_client.dart';
import 'fakes/fake_service_starter.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues(<String, Object>{});
  });

  group('connectionsLoaderProvider', () {
    test('seeds the default connection on first launch', () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      await container.read(connectionsLoaderProvider.future);

      final connections = container.read(connectionsProvider);
      expect(connections, <SavedConnection>[defaultConnection]);
      expect(container.read(activeConnectionIdProvider), defaultConnection.id);
    });

    test('restores a previously persisted list and active id', () async {
      SharedPreferences.setMockInitialValues(<String, Object>{
        'manytier.connections':
            '[{"id":"a","label":"A","host":"1.2.3.4","port":1000},'
            '{"id":"b","label":"B","host":"5.6.7.8","port":2000,"manualToken":"tok"}]',
        'manytier.connections.activeId': 'b',
      });
      final container = ProviderContainer();
      addTearDown(container.dispose);

      await container.read(connectionsLoaderProvider.future);

      final connections = container.read(connectionsProvider);
      expect(connections, hasLength(2));
      expect(connections[1].manualToken, 'tok');
      expect(container.read(activeConnectionIdProvider), 'b');
      expect(container.read(connectionSettingsProvider).label, 'B');
    });

    test(
      'falls back to the first connection when the active id is stale',
      () async {
        SharedPreferences.setMockInitialValues(<String, Object>{
          'manytier.connections':
              '[{"id":"a","label":"A","host":"1.2.3.4","port":1000}]',
          'manytier.connections.activeId': 'ghost',
        });
        final container = ProviderContainer();
        addTearDown(container.dispose);

        await container.read(connectionsLoaderProvider.future);

        expect(container.read(activeConnectionIdProvider), 'a');
      },
    );

    test(
      'falls back to the default connection on corrupt persisted JSON',
      () async {
        SharedPreferences.setMockInitialValues(<String, Object>{
          'manytier.connections': 'not valid json',
        });
        final container = ProviderContainer();
        addTearDown(container.dispose);

        await container.read(connectionsLoaderProvider.future);

        expect(container.read(connectionsProvider), <SavedConnection>[
          defaultConnection,
        ]);
      },
    );
  });

  group('ConnectionsController', () {
    test('add appends and switches to the new connection', () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      await container.read(connectionsLoaderProvider.future);

      const added = SavedConnection(
        id: 'new',
        label: 'New',
        host: '10.0.0.1',
        port: 42,
      );
      container.read(connectionsControllerProvider).add(added);

      expect(container.read(connectionsProvider), <SavedConnection>[
        defaultConnection,
        added,
      ]);
      expect(container.read(activeConnectionIdProvider), 'new');
    });

    test('switchTo changes the active id when it exists', () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      await container.read(connectionsLoaderProvider.future);
      container
          .read(connectionsControllerProvider)
          .add(const SavedConnection(id: 'new', label: 'New'));

      container
          .read(connectionsControllerProvider)
          .switchTo(defaultConnection.id);

      expect(container.read(activeConnectionIdProvider), defaultConnection.id);
    });

    test('switchTo is a no-op for an unknown id', () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      await container.read(connectionsLoaderProvider.future);

      container.read(connectionsControllerProvider).switchTo('does-not-exist');

      expect(container.read(activeConnectionIdProvider), defaultConnection.id);
    });

    test(
      'forget removes a connection and reassigns active if it was active',
      () async {
        final container = ProviderContainer();
        addTearDown(container.dispose);
        await container.read(connectionsLoaderProvider.future);
        container
            .read(connectionsControllerProvider)
            .add(const SavedConnection(id: 'new', label: 'New'));
        expect(container.read(activeConnectionIdProvider), 'new');

        container.read(connectionsControllerProvider).forget('new');

        expect(container.read(connectionsProvider), <SavedConnection>[
          defaultConnection,
        ]);
        expect(
          container.read(activeConnectionIdProvider),
          defaultConnection.id,
        );
      },
    );

    test(
      'forget clears active id when the last connection is removed',
      () async {
        final container = ProviderContainer();
        addTearDown(container.dispose);
        await container.read(connectionsLoaderProvider.future);

        container
            .read(connectionsControllerProvider)
            .forget(defaultConnection.id);

        expect(container.read(connectionsProvider), isEmpty);
        expect(container.read(activeConnectionIdProvider), isNull);
        // Falls back to the hardcoded default when nothing is saved at all.
        expect(container.read(connectionSettingsProvider), defaultConnection);
      },
    );

    test('update replaces the matching connection in place', () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      await container.read(connectionsLoaderProvider.future);

      container
          .read(connectionsControllerProvider)
          .update(defaultConnection.copyWith(manualToken: 'secret'));

      expect(container.read(connectionsProvider).single.manualToken, 'secret');
    });
  });

  group('DaemonPoller lifecycle', () {
    late TestWidgetsFlutterBinding binding;

    setUp(() {
      binding = TestWidgetsFlutterBinding.ensureInitialized();
      binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    });

    tearDown(() {
      binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    });

    test(
      'pauses periodic polling while hidden and resumes with a refresh',
      () async {
        final client = FakeManyTierClient();
        final poller = DaemonPoller(
          client,
          binding: binding,
          pollInterval: const Duration(hours: 1),
        );
        addTearDown(poller.dispose);

        await Future<void>.delayed(Duration.zero);

        expect(poller.isPolling, isTrue);
        expect(client.statusCalls, 1);
        expect(client.networksCalls, 1);
        expect(client.peersCalls, 1);

        binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
        expect(poller.isPolling, isTrue);

        binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
        expect(poller.isPolling, isFalse);

        await poller.refresh();
        expect(client.statusCalls, 2);
        expect(client.networksCalls, 2);
        expect(client.peersCalls, 2);

        binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
        await Future<void>.delayed(Duration.zero);

        expect(poller.isPolling, isTrue);
        expect(client.statusCalls, 3);
        expect(client.networksCalls, 3);
        expect(client.peersCalls, 3);
      },
    );

    test('records bounded latency history per active peer', () async {
      ManyTierPeer peer(int latency) => ManyTierPeer(
        address: 'abcdef0123',
        paths: const <ManyTierPeerPath>[],
        latency: latency,
        role: 'LEAF',
      );

      final client = FakeManyTierClient(peers: <ManyTierPeer>[peer(10)]);
      final poller = DaemonPoller(
        client,
        binding: binding,
        pollInterval: const Duration(hours: 1),
      );
      addTearDown(poller.dispose);

      await Future<void>.delayed(Duration.zero);
      expect(
        (poller.state.requireValue as DaemonConnected)
            .peerLatencyHistory['abcdef0123'],
        <int>[10],
      );

      client.peers_ = <ManyTierPeer>[peer(20)];
      await poller.refresh();
      expect(
        (poller.state.requireValue as DaemonConnected)
            .peerLatencyHistory['abcdef0123'],
        <int>[10, 20],
      );

      client.peers_ = <ManyTierPeer>[peer(-1)];
      await poller.refresh();
      expect(
        (poller.state.requireValue as DaemonConnected)
            .peerLatencyHistory['abcdef0123'],
        <int>[10, 20],
      );

      for (int i = 0; i < 30; i++) {
        client.peers_ = <ManyTierPeer>[peer(100 + i)];
        await poller.refresh();
      }
      expect(
        (poller.state.requireValue as DaemonConnected)
            .peerLatencyHistory['abcdef0123'],
        List<int>.generate(24, (int i) => 106 + i),
      );

      client.peers_ = const <ManyTierPeer>[];
      await poller.refresh();
      expect(
        (poller.state.requireValue as DaemonConnected).peerLatencyHistory,
        isNot(contains('abcdef0123')),
      );
    });
  });

  group('SavedConnection JSON round-trip', () {
    test('toJson/fromJson preserves all fields', () {
      const original = SavedConnection(
        id: 'x',
        label: 'X',
        host: '9.9.9.9',
        port: 1234,
        manualToken: 'tok',
      );

      final restored = SavedConnection.fromJson(original.toJson());

      expect(restored.id, original.id);
      expect(restored.label, original.label);
      expect(restored.host, original.host);
      expect(restored.port, original.port);
      expect(restored.manualToken, original.manualToken);
    });
  });

  group('ServiceLifecycleController', () {
    test('starts a local service with the active connection port', () async {
      final starter = FakeServiceStarter();
      final container = ProviderContainer(
        overrides: <Override>[
          manyTierServiceStarterProvider.overrideWithValue(starter),
        ],
      );
      addTearDown(container.dispose);

      await container
          .read(serviceLifecycleProvider.notifier)
          .start(
            const SavedConnection(id: 'local', label: 'Local', port: 4242),
          );

      expect(starter.starts, hasLength(1));
      expect(starter.starts.single.apiPort, 4242);
      expect(starter.starts.single.udpPort, 9993);
      expect(starter.starts.single.dataDir, '/tmp/manytier-test');
      expect(
        container.read(serviceLifecycleProvider).startedService?.pid,
        4242,
      );
    });

    test('rejects remote hosts without starting a process', () async {
      final starter = FakeServiceStarter();
      final container = ProviderContainer(
        overrides: <Override>[
          manyTierServiceStarterProvider.overrideWithValue(starter),
        ],
      );
      addTearDown(container.dispose);

      await container
          .read(serviceLifecycleProvider.notifier)
          .start(
            const SavedConnection(
              id: 'remote',
              label: 'Remote',
              host: '192.0.2.10',
            ),
          );

      expect(starter.starts, isEmpty);
      expect(
        container.read(serviceLifecycleProvider).error,
        contains('local daemon'),
      );
    });

    test('stop terminates the app-started process', () async {
      final starter = FakeServiceStarter();
      final container = ProviderContainer(
        overrides: <Override>[
          manyTierServiceStarterProvider.overrideWithValue(starter),
        ],
      );
      addTearDown(container.dispose);

      await container
          .read(serviceLifecycleProvider.notifier)
          .start(defaultConnection);
      await container.read(serviceLifecycleProvider.notifier).stop();

      expect(starter.stops, 1);
      expect(container.read(serviceLifecycleProvider).startedService, isNull);
    });
  });
}
