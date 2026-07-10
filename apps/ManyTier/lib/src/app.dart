import 'package:flutter/widgets.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manyui/manyui.dart';

import 'networks/networks_page.dart';
import 'theme.dart';

class ManyTierApp extends ConsumerWidget {
  const ManyTierApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final mode = ref.watch(themeModeProvider);
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
