import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manyui/manyui.dart';
import 'package:manytier_app/src/api/manytier_client.dart';
import 'package:manytier_app/src/networks/networks_page.dart';
import 'package:manytier_app/src/state/connection.dart';

import 'fakes/fake_manytier_client.dart';

Widget _app(FakeManyTierClient client) {
  return ProviderScope(
    overrides: <Override>[manyTierClientProvider.overrideWithValue(client)],
    child: const MWidgetsApp(
      debugShowCheckedModeBanner: false,
      home: NetworksPage(),
    ),
  );
}

Future<void> _settle(WidgetTester tester) async {
  for (int i = 0; i < 4; i++) {
    await tester.pump();
  }
}

Future<void> _useTallSurface(WidgetTester tester) =>
    tester.binding.setSurfaceSize(const Size(900, 1600));

void main() {
  group('NetworksPage peers', () {
    testWidgets('renders peer latency text and trend semantics', (
      tester,
    ) async {
      final semantics = tester.ensureSemantics();

      try {
        final client = FakeManyTierClient(
          peers: const <ManyTierPeer>[
            ManyTierPeer(
              address: '1122334455',
              paths: <ManyTierPeerPath>[
                ManyTierPeerPath(
                  address: '192.0.2.1:9993',
                  active: true,
                  lastReceive: 0,
                ),
              ],
              latency: 42,
              role: 'ROOT',
            ),
          ],
        );

        await tester.pumpWidget(_app(client));
        await _useTallSurface(tester);
        await _settle(tester);

        expect(find.text('1122334455'), findsOneWidget);
        expect(find.text('42 ms'), findsOneWidget);
        expect(find.text('1 path'), findsOneWidget);
        expect(
          find.bySemanticsLabel('Latency trend for 1122334455'),
          findsOneWidget,
        );
      } finally {
        semantics.dispose();
      }
    });
  });
}
