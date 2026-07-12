import 'embedded_node.dart';
import 'embedded_node_runtime.dart';

const bool embeddedNodeRuntimeEntryPointSupported = false;
const String embeddedNodeRuntimeEntryPointUnsupportedReason =
    'Embedded node runtime entry point is only available on native IO platforms.';

Future<EmbeddedNodeRuntime> startNativeEmbeddedNodeRuntime(
  EmbeddedNodeRuntimeConfig config,
) {
  throw const EmbeddedNodeException(
    'Embedded node runtime entry point is only available on native IO platforms.',
  );
}
