import 'dart:typed_data';

import 'embedded_node.dart';

const bool embeddedNodeRuntimeSupported = false;
const String embeddedNodeRuntimeUnsupportedReason =
    'Embedded node runtime is only available on native platforms.';

EmbeddedNodeSession createNativeEmbeddedNodeSession({
  required String identitySecret,
  required Uint8List planet,
  int initialPacketId = 1,
  String? libraryPath,
}) {
  throw const EmbeddedNodeException(
    'Embedded node runtime is only available on native platforms.',
  );
}
