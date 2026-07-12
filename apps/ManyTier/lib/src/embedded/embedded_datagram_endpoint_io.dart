import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'embedded_node.dart';
import 'embedded_node_host.dart';

const bool embeddedDatagramEndpointSupported = true;
const String? embeddedDatagramEndpointUnsupportedReason = null;

Future<EmbeddedDatagramEndpoint> createRawSocketEmbeddedDatagramEndpoint({
  String host = '0.0.0.0',
  int port = 9993,
  bool reuseAddress = true,
  bool reusePort = false,
}) async {
  final address = InternetAddress(host);
  final socket = await RawDatagramSocket.bind(
    address,
    port,
    reuseAddress: reuseAddress,
    reusePort: reusePort,
  );
  return RawSocketEmbeddedDatagramEndpoint._(socket);
}

class RawSocketEmbeddedDatagramEndpoint implements EmbeddedDatagramEndpoint {
  RawSocketEmbeddedDatagramEndpoint._(this._socket) {
    _subscription = _socket.listen(
      _handleSocketEvent,
      onError: _datagrams.addError,
      onDone: _datagrams.close,
    );
  }

  final RawDatagramSocket _socket;
  final StreamController<EmbeddedDatagram> _datagrams =
      StreamController<EmbeddedDatagram>.broadcast();
  late final StreamSubscription<RawSocketEvent> _subscription;
  bool _closed = false;

  @override
  Stream<EmbeddedDatagram> get datagrams => _datagrams.stream;

  @override
  Future<void> send(Uint8List data, EmbeddedSocketAddress address) async {
    _checkOpen();
    final sent = _socket.send(
      data,
      _internetAddressFromSocketAddress(address),
      address.port,
    );
    if (sent != data.length) {
      throw EmbeddedNodeException(
        'UDP send wrote $sent of ${data.length} bytes.',
      );
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription.cancel();
    _socket.close();
    await _datagrams.close();
  }

  void _handleSocketEvent(RawSocketEvent event) {
    if (event != RawSocketEvent.read) return;
    for (
      Datagram? datagram = _socket.receive();
      datagram != null;
      datagram = _socket.receive()
    ) {
      _datagrams.add(
        EmbeddedDatagram(
          data: datagram.data,
          from: _socketAddressFromInternetAddress(
            datagram.address,
            datagram.port,
          ),
        ),
      );
    }
  }

  void _checkOpen() {
    if (_closed) {
      throw const EmbeddedNodeException('UDP endpoint is closed.');
    }
  }
}

InternetAddress _internetAddressFromSocketAddress(
  EmbeddedSocketAddress address,
) {
  if (address.family == 4) {
    return InternetAddress.fromRawAddress(
      Uint8List.fromList(address.ipv4Octets),
      type: InternetAddressType.IPv4,
    );
  }
  return InternetAddress.fromRawAddress(
    Uint8List.fromList(address.address),
    type: InternetAddressType.IPv6,
  );
}

EmbeddedSocketAddress _socketAddressFromInternetAddress(
  InternetAddress address,
  int port,
) {
  final raw = address.rawAddress;
  if (raw.length == 4) {
    return EmbeddedSocketAddress.ipv4(raw[0], raw[1], raw[2], raw[3], port);
  }
  if (raw.length == 16) {
    return EmbeddedSocketAddress.ipv6(raw, port);
  }
  throw EmbeddedNodeException(
    'Unsupported UDP address length ${raw.length} for ${address.address}.',
  );
}
