import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manytier_app/src/embedded/embedded_node.dart';
import 'package:manytier_app/src/state/embedded_runtime_lifecycle.dart';

import 'fakes/fake_embedded_runtime_starter.dart';

void main() {
  test('starts with default config and stops the runtime', () async {
    final starter = FakeEmbeddedRuntimeStarter();
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
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

  test('reports unsupported platforms without starting', () async {
    final starter = FakeEmbeddedRuntimeStarter(supported: false);
    final container = ProviderContainer(
      overrides: <Override>[
        embeddedRuntimeStarterProvider.overrideWithValue(starter),
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
      ],
    );
    addTearDown(starter.dispose);

    await container.read(embeddedRuntimeLifecycleProvider.notifier).start();
    container.dispose();

    expect(starter.closes, 1);
  });
}
