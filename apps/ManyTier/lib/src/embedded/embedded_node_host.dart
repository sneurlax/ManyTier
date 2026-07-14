import 'dart:async';
import 'dart:typed_data';

import 'embedded_node.dart';

typedef EmbeddedNodeClock = int Function();

int embeddedNodeSystemClockMs() => DateTime.now().millisecondsSinceEpoch;

class EmbeddedDatagram {
  EmbeddedDatagram({required List<int> data, required this.from})
    : data = Uint8List.fromList(data);

  final Uint8List data;
  final EmbeddedSocketAddress from;
}

abstract interface class EmbeddedDatagramEndpoint {
  Stream<EmbeddedDatagram> get datagrams;
  Future<void> send(Uint8List data, EmbeddedSocketAddress address);
  Future<void> close();
}

class EmbeddedNodeHost {
  EmbeddedNodeHost({
    required EmbeddedNodeSession session,
    required EmbeddedDatagramEndpoint endpoint,
    EmbeddedNodeClock clock = embeddedNodeSystemClockMs,
    this.tickInterval = const Duration(milliseconds: 5000),
    this.closeEndpoint = true,
  }) : _session = session,
       _endpoint = endpoint,
       _clock = clock;

  final EmbeddedNodeSession _session;
  final EmbeddedDatagramEndpoint _endpoint;
  final EmbeddedNodeClock _clock;
  final StreamController<EmbeddedNodeAction> _actions =
      StreamController<EmbeddedNodeAction>.broadcast(sync: true);
  final Duration tickInterval;
  final bool closeEndpoint;

  StreamSubscription<EmbeddedDatagram>? _datagramSubscription;
  Timer? _tickTimer;
  Future<void> _queue = Future<void>.value();
  bool _started = false;
  bool _closed = false;

  Stream<EmbeddedNodeAction> get actions => _actions.stream;
  bool get isStarted => _started;
  Future<void> get idle => _queue;

  Future<void> start({int? nowMs}) {
    _checkOpen();
    if (_started) return _queue;
    _started = true;
    _datagramSubscription = _endpoint.datagrams.listen((datagram) {
      _enqueue(() => _receiveDatagram(datagram)).catchError(_actions.addError);
    }, onError: _actions.addError);
    if (tickInterval > Duration.zero) {
      _tickTimer = Timer.periodic(tickInterval, (_) {
        tick().catchError(_actions.addError);
      });
    }
    return _enqueue(
      () => _handleActions(_session.bootstrap(nowMs ?? _clock())),
    );
  }

  Future<void> tick({int? nowMs}) {
    _checkOpen();
    return _enqueue(() => _handleActions(_session.tick(nowMs ?? _clock())));
  }

  Future<void> receiveDatagram(EmbeddedDatagram datagram, {int? nowMs}) {
    _checkOpen();
    return _enqueue(() => _receiveDatagram(datagram, nowMs: nowMs));
  }

  Future<void> receiveVirtualPacket(
    int networkId,
    Uint8List packet, {
    int? nowMs,
  }) {
    _checkOpen();
    final ethertype = _ethertypeForVirtualPacket(packet);
    if (ethertype == null) return Future<void>.value();
    return _enqueue(
      () => _handleActions(
        _session.processVirtualFrame(
          networkId,
          ethertype,
          packet,
          nowMs ?? _clock(),
        ),
      ),
    );
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _tickTimer?.cancel();
    await _datagramSubscription?.cancel();
    try {
      await _queue;
    } finally {
      _session.close();
      if (closeEndpoint) {
        await _endpoint.close();
      }
      await _actions.close();
    }
  }

  Future<void> _receiveDatagram(EmbeddedDatagram datagram, {int? nowMs}) async {
    await _handleActions(
      _session.receivePacket(datagram.data, datagram.from, nowMs ?? _clock()),
    );
  }

  Future<void> _handleActions(List<EmbeddedNodeAction> actions) async {
    for (final action in actions) {
      if (action.kind == EmbeddedNodeActionKind.sendTo) {
        final address = action.socketAddress;
        if (address == null) {
          throw const EmbeddedNodeException(
            'SendTo action is missing a socket address.',
          );
        }
        await _endpoint.send(Uint8List.fromList(action.data), address);
      } else if (action.kind == EmbeddedNodeActionKind.whoisNeeded) {
        await _handleActions(
          _session.sendWhois(action.zeroTierAddressList, _clock()),
        );
      } else {
        _actions.add(action);
      }
    }
    _session.clearActions();
  }

  Future<void> _enqueue(Future<void> Function() operation) {
    final next = _queue.then((_) {
      if (_closed) return Future<void>.value();
      return operation();
    });
    _queue = next.catchError((Object _) {});
    return next;
  }

  void _checkOpen() {
    if (_closed) {
      throw const EmbeddedNodeException('Embedded node host is closed.');
    }
  }
}

int? _ethertypeForVirtualPacket(Uint8List packet) {
  if (packet.isEmpty) return null;
  return switch (packet[0] >> 4) {
    4 => 0x0800,
    6 => 0x86dd,
    _ => null,
  };
}
