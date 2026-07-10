import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manyui/manyui.dart';

final themeModeProvider = StateProvider<MThemeMode>((ref) => MThemeMode.system);
