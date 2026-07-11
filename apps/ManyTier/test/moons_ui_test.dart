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
    overrides: <Override>[
      manyTierClientProvider.overrideWithValue(client),
    ],
    child: const MWidgetsApp(
      debugShowCheckedModeBanner: false,
      home: NetworksPage(),
    ),
  );
}

/// [daemonConnectionProvider]/[moonsProvider] each resolve over a couple of
/// chained futures (settings -> token -> client -> status/networks/peers/
/// moons) before the dashboard replaces the loading state, so a single pump
/// isn't enough -- settle with a few extra frames instead of pumpAndSettle
/// (DaemonPoller's periodic Timer never quiesces, so pumpAndSettle hangs).
Future<void> _settle(WidgetTester tester) async {
  for (int i = 0; i < 4; i++) {
    await tester.pump();
  }
}

Finder get _moonIdField => find.byWidgetPredicate(
    (Widget w) => w is MTextField && w.placeholder == '16-digit moon ID');

/// The dashboard (status + networks + moons) is taller than the default
/// 800x600 test surface, which puts the Deorbit button off-screen for
/// hit-testing -- use a bigger surface instead of scrolling to find it.
Future<void> _useTallSurface(WidgetTester tester) =>
    tester.binding.setSurfaceSize(const Size(800, 2000));

void main() {
  group('Moons UI', () {
    testWidgets('shows the empty state when no moons are orbited',
        (tester) async {
      final client = FakeManyTierClient();
      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.text('Not orbiting any moons.'), findsOneWidget);
    });

    testWidgets('lists orbited moons with their root count', (tester) async {
      final client = FakeManyTierClient(moons: <Moon>[
        const Moon(id: 'aaaaaaaaaaaaaaaa', timestamp: 0, roots: <MoonRoot>[
          MoonRoot(address: 'abcdef0123', endpoints: <String>['1.2.3.4/9993']),
        ]),
      ]);
      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.text('aaaaaaaaaaaaaaaa'), findsOneWidget);
      expect(find.text('1 root'), findsOneWidget);
    });

    testWidgets('orbit requires a well-formed id before enabling the button',
        (tester) async {
      final client = FakeManyTierClient();
      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      final orbitButton = find.widgetWithText(MButton, 'Orbit');
      expect(tester.widget<MButton>(orbitButton).onPressed, isNull);

      await tester.enterText(_moonIdField, 'aaaaaaaaaaaaaaaa');
      await tester.pump();

      expect(tester.widget<MButton>(orbitButton).onPressed, isNotNull);
    });

    testWidgets('orbiting a moon calls the client and refreshes the list',
        (tester) async {
      final client = FakeManyTierClient();
      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      await tester.enterText(_moonIdField, 'bbbbbbbbbbbbbbbb');
      await tester.pump();
      await tester.tap(find.widgetWithText(MButton, 'Orbit'));
      await _settle(tester);

      expect(client.orbitCalls, 1);
      expect(find.text('bbbbbbbbbbbbbbbb'), findsOneWidget);
    });

    testWidgets('deorbit requires confirmation and calls the client',
        (tester) async {
      final client = FakeManyTierClient(moons: <Moon>[
        const Moon(id: 'cccccccccccccccc', timestamp: 0, roots: <MoonRoot>[]),
      ]);
      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      await tester.tap(find.widgetWithText(MButton, 'Deorbit'));
      await _settle(tester);
      expect(find.text('Deorbit moon?'), findsOneWidget);

      await tester.tap(find.widgetWithText(MButton, 'Deorbit').last);
      await _settle(tester);

      expect(client.deorbitCalls, 1);
      expect(find.text('Not orbiting any moons.'), findsOneWidget);
    });

    testWidgets('cancelling deorbit does not call the client',
        (tester) async {
      final client = FakeManyTierClient(moons: <Moon>[
        const Moon(id: 'dddddddddddddddd', timestamp: 0, roots: <MoonRoot>[]),
      ]);
      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      await tester.tap(find.widgetWithText(MButton, 'Deorbit'));
      await _settle(tester);
      await tester.tap(find.widgetWithText(MButton, 'Cancel'));
      await tester.pump();

      expect(client.deorbitCalls, 0);
      expect(find.text('dddddddddddddddd'), findsOneWidget);
    });

    testWidgets('a failed deorbit shows an inline error, not a crash',
        (tester) async {
      final client = FakeManyTierClient(moons: <Moon>[
        const Moon(id: 'eeeeeeeeeeeeeeee', timestamp: 0, roots: <MoonRoot>[]),
      ])..nextActionError = const ApiError(500, 'moon busy');
      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      await tester.tap(find.widgetWithText(MButton, 'Deorbit'));
      await _settle(tester);
      await tester.tap(find.widgetWithText(MButton, 'Deorbit').last);
      await _settle(tester);

      expect(find.text('moon busy'), findsOneWidget);
      expect(find.text('eeeeeeeeeeeeeeee'), findsOneWidget);
    });
  });
}
