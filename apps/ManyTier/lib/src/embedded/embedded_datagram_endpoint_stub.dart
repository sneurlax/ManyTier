import 'embedded_node.dart';
import 'embedded_node_host.dart';

const bool embeddedDatagramEndpointSupported = false;
const String embeddedDatagramEndpointUnsupportedReason =
    'Raw UDP datagram endpoints are only available on dart:io platforms.';

Future<EmbeddedDatagramEndpoint> createRawSocketEmbeddedDatagramEndpoint({
  String host = '0.0.0.0',
  int port = 9993,
  bool reuseAddress = true,
  bool reusePort = false,
}) {
  throw const EmbeddedNodeException(
    'Raw UDP datagram endpoints are only available on dart:io platforms.',
  );
}
