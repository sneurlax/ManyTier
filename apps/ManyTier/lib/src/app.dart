import 'package:flutter/widgets.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manyui/manyui.dart';
import 'package:manyui_riverpod/manyui_riverpod.dart';

import 'networks/networks_page.dart';
import 'state/connection.dart';
import 'theme.dart';

class ManyTierApp extends ConsumerWidget {
  const ManyTierApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final mode = ref.watchMThemeMode(themeModeProvider);
    // Neither provider holds widget-visible state -- watching just
    // instantiates them: one loads persisted settings at startup, the
    // other listens for changes and writes them back.
    ref.watch(connectionsLoaderProvider);
    ref.watch(connectionsPersistenceProvider);
    return MWidgetsApp(
      title: 'ManyTier',
      theme: MThemeData.light(),
      darkTheme: MThemeData.dark(),
      themeMode: mode,
      debugShowCheckedModeBanner: false,
      home: const NetworksPage(),
    );
  }
}
