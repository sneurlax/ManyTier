import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/embedded/embedded_virtual_network.dart';
import 'package:manytier_app/src/state/embedded_runtime_lifecycle.dart';

import 'fakes/fake_embedded_runtime_starter.dart';
import 'fakes/fake_embedded_virtual_network.dart';

void main() {
  test('starts with default config and stops the runtime', () async {
    final starter = FakeEmbeddedRuntimeStarter();
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
        embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
          _unsupportedVirtualNetworkResolver,
        ),
      ],
    );
    addTearDown(container.dispose);
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();

    expect(starter.starts, hasLength(1));
    expect(starter.starts.single.dataDir, '/tmp/manytier-test');
    expect(starter.starts.single.udpHost, '0.0.0.0');
    expect(starter.starts.single.udpPort, 9993);
    expect(
      container.read(embeddedRuntimeLifecycleProvider).runtime?.addressHex,
      'faa900da4a',
    );

    await container.read(embeddedRuntimeLifecycleProvider.notifier).stop();

    expect(starter.closes, 1);
    expect(container.read(embeddedRuntimeLifecycleProvider).runtime, isNull);
  });

  test('tracks actions emitted by the runtime', () async {
    final starter = FakeEmbeddedRuntimeStarter();
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
        embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
          _unsupportedVirtualNetworkResolver,
        ),
      ],
    );
    addTearDown(container.dispose);
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();
    starter.actions.add(
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.networkConfigured,
        networkId: 0x8056c2e21c000001,
      ),
    );
    await Future<void>.delayed(Duration.zero);

    final state = container.read(embeddedRuntimeLifecycleProvider);
    expect(state.actionCount, 1);
    expect(state.lastAction?.kind, EmbeddedNodeActionKind.networkConfigured);
  });

  test(
    'routes virtual-network actions through configured interfaces',
    () async {
      final starter = FakeEmbeddedRuntimeStarter();
      final virtualNetworks = FakeEmbeddedVirtualNetworkFactory();
      final container = ProviderContainer(
        overrides: <Override>[
          embeddedRuntimeStarterProvider.overrideWithValue(starter),
          embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
            () async => virtualNetworks,
          ),
        ],
      );
      addTearDown(container.dispose);
      addTearDown(starter.dispose);

      await container.read(embeddedRuntimeLifecycleProvider.notifier).start();
      starter.actions.add(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.networkConfigured,
          networkId: 0x8056c2e21c000001,
          data: const <int>[1, 2, 3],
        ),
      );
      await Future<void>.delayed(Duration.zero);
      await Future<void>.delayed(Duration.zero);

      expect(virtualNetworks.creates, hasLength(1));
      expect(virtualNetworks.creates.single.networkId, 0x8056c2e21c000001);
      expect(virtualNetworks.creates.single.nodeAddress, <int>[
        0xfa,
        0xa9,
        0,
        0xda,
        0x4a,
      ]);
      expect(virtualNetworks.creates.single.dictData, <int>[1, 2, 3]);

      starter.actions.add(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.frameReceived,
          networkId: 0x8056c2e21c000001,
          ethertype: 0x0800,
          data: const <int>[0x45, 1],
        ),
      );
      starter.actions.add(
        EmbeddedNodeAction(
          kind: EmbeddedNodeActionKind.localReply,
          networkId: 0x8056c2e21c000001,
          ethertype: 0x0806,
          data: const <int>[0xaa, 0xbb],
        ),
      );
      await Future<void>.delayed(Duration.zero);
      await Future<void>.delayed(Duration.zero);

      expect(virtualNetworks.interfaces.single.writes, hasLength(2));
      expect(virtualNetworks.interfaces.single.writes[0], <int>[0x45, 1]);
      expect(virtualNetworks.interfaces.single.writes[1], <int>[0xaa, 0xbb]);

      await virtualNetworks.interfaces.single.addPacket(<int>[0x45, 0, 0, 20]);

      expect(starter.virtualPackets, hasLength(1));
      expect(starter.virtualPackets.single.networkId, 0x8056c2e21c000001);
      expect(starter.virtualPackets.single.packet, <int>[0x45, 0, 0, 20]);
      expect(container.read(embeddedRuntimeLifecycleProvider).actionCount, 3);
    },
  );

  test('stopping a runtime closes virtual interfaces', () async {
    final starter = FakeEmbeddedRuntimeStarter();
    final virtualNetworks = FakeEmbeddedVirtualNetworkFactory();
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
        embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
          () async => virtualNetworks,
        ),
      ],
    );
    addTearDown(container.dispose);
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();
    starter.actions.add(
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.networkConfigured,
        networkId: 0x8056c2e21c000001,
      ),
    );
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).stop();

    expect(virtualNetworks.interfaces.single.closeCalls, 1);
    expect(starter.closes, 1);
  });

  test('resolved unsupported virtual-network factories are no-ops', () async {
    final starter = FakeEmbeddedRuntimeStarter();
    final virtualNetworks = FakeEmbeddedVirtualNetworkFactory(
      supported: false,
      reason: 'packet tunnel unavailable',
    );
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
        embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
          () async => virtualNetworks,
        ),
      ],
    );
    addTearDown(container.dispose);
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();
    starter.actions.add(
      EmbeddedNodeAction(
        kind: EmbeddedNodeActionKind.networkConfigured,
        networkId: 0x8056c2e21c000001,
      ),
    );
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);

    expect(starter.starts, hasLength(1));
    expect(virtualNetworks.creates, isEmpty);
    expect(container.read(embeddedRuntimeLifecycleProvider).error, isNull);
  });

  test('stopping a runtime disposes the resolved virtual factory', () async {
    final starter = FakeEmbeddedRuntimeStarter();
    final virtualNetworks = DisposableFakeEmbeddedVirtualNetworkFactory();
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
        embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
          () async => virtualNetworks,
        ),
      ],
    );
    addTearDown(container.dispose);
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();

    await container.read(embeddedRuntimeLifecycleProvider.notifier).stop();

    expect(virtualNetworks.disposeCalls, 1);
    expect(starter.closes, 1);
  });

  test(
    'closes a started runtime when virtual factory resolution fails',
    () async {
      final starter = FakeEmbeddedRuntimeStarter();
      final container = ProviderContainer(
        overrides: <Override>[
          embeddedRuntimeStarterProvider.overrideWithValue(starter),
          embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
            () async {
              throw StateError('support probe failed');
            },
          ),
        ],
      );
      addTearDown(container.dispose);
      addTearDown(starter.dispose);

      await container.read(embeddedRuntimeLifecycleProvider.notifier).start();

      final state = container.read(embeddedRuntimeLifecycleProvider);
      expect(starter.starts, hasLength(1));
      expect(starter.closes, 1);
      expect(state.runtime, isNull);
      expect(state.error, contains('support probe failed'));
    },
  );

  test('reports unsupported platforms without starting', () async {
    final starter = FakeEmbeddedRuntimeStarter(supported: false);
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
        embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
          _unsupportedVirtualNetworkResolver,
        ),
      ],
    );
    addTearDown(container.dispose);
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();

    expect(starter.starts, isEmpty);
    expect(
      container.read(embeddedRuntimeLifecycleProvider).error,
      'embedded runtime unavailable',
    );
  });

  test('disposes a running runtime', () async {
    final starter = FakeEmbeddedRuntimeStarter();
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
        embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
          _unsupportedVirtualNetworkResolver,
        ),
      ],
    );
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();
    container.dispose();

    expect(starter.closes, 1);
  });
}

Future<EmbeddedVirtualNetworkFactory>
_unsupportedVirtualNetworkResolver() async {
  return const UnsupportedEmbeddedVirtualNetworkFactory();
}
