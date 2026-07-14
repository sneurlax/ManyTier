import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'embedded_node.dart';

typedef EmbeddedVirtualPacketSink =
    Future<void> Function(int networkId, Uint8List packet);

typedef EmbeddedVirtualNetworkErrorHandler =
    void Function(Object error, StackTrace stackTrace);

class EmbeddedVirtualNetworkConfig {
  EmbeddedVirtualNetworkConfig({
    required this.networkId,
    required Uint8List nodeAddress,
    required Uint8List dictData,
    EmbeddedVirtualNetworkSettings? settings,
    String? interfaceName,
  }) : nodeAddress = Uint8List.fromList(nodeAddress),
       dictData = Uint8List.fromList(dictData),
       settings =
           settings ??
           EmbeddedVirtualNetworkSettings.fromDictionaryData(dictData),
       interfaceName =
           interfaceName ?? embeddedVirtualNetworkName(networkId, nodeAddress) {
    _checkNodeAddress(nodeAddress);
  }

  final int networkId;
  final Uint8List nodeAddress;
  final Uint8List dictData;
  final EmbeddedVirtualNetworkSettings settings;
  final String interfaceName;
}

class EmbeddedVirtualNetworkSettings {
  EmbeddedVirtualNetworkSettings({
    this.mtu = defaultMtu,
    List<EmbeddedVirtualNetworkAddress> managedAddresses =
        const <EmbeddedVirtualNetworkAddress>[],
    List<EmbeddedVirtualNetworkRoute> routes =
        const <EmbeddedVirtualNetworkRoute>[],
  }) : managedAddresses = List<EmbeddedVirtualNetworkAddress>.unmodifiable(
         managedAddresses,
       ),
       routes = List<EmbeddedVirtualNetworkRoute>.unmodifiable(routes);

  factory EmbeddedVirtualNetworkSettings.fromDictionaryData(
    List<int> dictData,
  ) {
    final dictionary = _ZeroTierDictionary.tryParse(dictData);
    if (dictionary == null) {
      return EmbeddedVirtualNetworkSettings();
    }
    return EmbeddedVirtualNetworkSettings(
      mtu: dictionary.hexInt('mtu') ?? defaultMtu,
      managedAddresses: _parseManagedAddresses(dictionary.binary('I')),
      routes: _parseManagedRoutes(dictionary.binary('RT')),
    );
  }

  static const int defaultMtu = 2800;

  final int mtu;
  final List<EmbeddedVirtualNetworkAddress> managedAddresses;
  final List<EmbeddedVirtualNetworkRoute> routes;
}

enum EmbeddedVirtualNetworkAddressFamily { ipv4, ipv6 }

class EmbeddedVirtualNetworkAddress {
  EmbeddedVirtualNetworkAddress({
    required this.family,
    required List<int> bytes,
    required this.prefixLength,
  }) : bytes = Uint8List.fromList(bytes) {
    final expectedLength = switch (family) {
      EmbeddedVirtualNetworkAddressFamily.ipv4 => 4,
      EmbeddedVirtualNetworkAddressFamily.ipv6 => 16,
    };
    if (bytes.length != expectedLength) {
      throw ArgumentError.value(
        bytes.length,
        'bytes.length',
        'must be $expectedLength for $family',
      );
    }
  }

  final EmbeddedVirtualNetworkAddressFamily family;
  final Uint8List bytes;
  final int prefixLength;

  String get address => switch (family) {
    EmbeddedVirtualNetworkAddressFamily.ipv4 => bytes.join('.'),
    EmbeddedVirtualNetworkAddressFamily.ipv6 => _ipv6AddressString(bytes),
  };

  String get cidr => '$address/$prefixLength';
}

class EmbeddedVirtualNetworkRoute {
  const EmbeddedVirtualNetworkRoute({
    required this.target,
    this.gateway,
    this.flags = 0,
  });

  final EmbeddedVirtualNetworkAddress target;
  final EmbeddedVirtualNetworkAddress? gateway;
  final int flags;
}

abstract interface class EmbeddedVirtualNetworkInterface {
  int get networkId;
  Stream<Uint8List> get packets;
  Future<void> write(Uint8List packet);
  Future<void> close();
}

abstract interface class EmbeddedVirtualNetworkFactory {
  bool get isSupported;
  String? get unsupportedReason;
  Future<EmbeddedVirtualNetworkInterface> create(
    EmbeddedVirtualNetworkConfig config,
  );
}

class UnsupportedEmbeddedVirtualNetworkFactory
    implements EmbeddedVirtualNetworkFactory {
  const UnsupportedEmbeddedVirtualNetworkFactory({
    this.unsupportedReason = 'Native virtual network devices are unavailable.',
  });

  @override
  final String? unsupportedReason;

  @override
  bool get isSupported => false;

  @override
  Future<EmbeddedVirtualNetworkInterface> create(
    EmbeddedVirtualNetworkConfig config,
  ) async {
    throw EmbeddedNodeException(
      unsupportedReason ?? 'Native virtual network devices are unavailable.',
    );
  }
}

class EmbeddedVirtualNetworkCoordinator {
  EmbeddedVirtualNetworkCoordinator({
    required EmbeddedVirtualNetworkFactory factory,
    required EmbeddedVirtualPacketSink packetSink,
    required Uint8List nodeAddress,
    EmbeddedVirtualNetworkErrorHandler? onError,
  }) : _factory = factory,
       _packetSink = packetSink,
       _nodeAddress = Uint8List.fromList(nodeAddress),
       _onError = onError;

  final EmbeddedVirtualNetworkFactory _factory;
  final EmbeddedVirtualPacketSink _packetSink;
  final Uint8List _nodeAddress;
  final EmbeddedVirtualNetworkErrorHandler? _onError;
  final Map<int, _VirtualNetworkBinding> _interfaces =
      <int, _VirtualNetworkBinding>{};

  Future<void> _queue = Future<void>.value();
  bool _closed = false;

  int get interfaceCount => _interfaces.length;

  Future<void> handleAction(EmbeddedNodeAction action) {
    if (_closed) return Future<void>.value();
    final next = _queue.then((_) async {
      if (_closed) return;
      await _handleAction(action);
    });
    _queue = next.catchError((Object _) {});
    return next;
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      await _queue;
    } catch (_) {
      // The caller that queued the action receives the original failure.
    }
    final bindings = List<_VirtualNetworkBinding>.from(_interfaces.values);
    _interfaces.clear();
    for (final binding in bindings) {
      await binding.close();
    }
  }

  Future<void> _handleAction(EmbeddedNodeAction action) {
    return switch (action.kind) {
      EmbeddedNodeActionKind.networkConfigured => _ensureInterface(action),
      EmbeddedNodeActionKind.frameReceived ||
      EmbeddedNodeActionKind.localReply => _writeToInterface(action),
      _ => Future<void>.value(),
    };
  }

  Future<void> _ensureInterface(EmbeddedNodeAction action) async {
    if (_interfaces.containsKey(action.networkId) || !_factory.isSupported) {
      return;
    }

    final network = await _factory.create(
      EmbeddedVirtualNetworkConfig(
        networkId: action.networkId,
        nodeAddress: _nodeAddress,
        dictData: Uint8List.fromList(action.data),
      ),
    );
    if (_closed || _interfaces.containsKey(action.networkId)) {
      await network.close();
      return;
    }

    late final StreamSubscription<Uint8List> subscription;
    subscription = network.packets.listen(
      (packet) {
        unawaited(_forwardPacket(action.networkId, packet));
      },
      onError: (Object error, StackTrace stackTrace) {
        _onError?.call(error, stackTrace);
      },
    );
    _interfaces[action.networkId] = _VirtualNetworkBinding(
      network: network,
      subscription: subscription,
    );
  }

  Future<void> _writeToInterface(EmbeddedNodeAction action) async {
    final binding = _interfaces[action.networkId];
    if (binding == null) return;
    await binding.network.write(Uint8List.fromList(action.data));
  }

  Future<void> _forwardPacket(int networkId, Uint8List packet) async {
    try {
      await _packetSink(networkId, Uint8List.fromList(packet));
    } on Object catch (error, stackTrace) {
      _onError?.call(error, stackTrace);
    }
  }
}

class _VirtualNetworkBinding {
  const _VirtualNetworkBinding({
    required this.network,
    required this.subscription,
  });

  final EmbeddedVirtualNetworkInterface network;
  final StreamSubscription<Uint8List> subscription;

  Future<void> close() async {
    await subscription.cancel();
    await network.close();
  }
}

String embeddedVirtualNetworkName(int networkId, List<int> nodeAddress) {
  _checkNodeAddress(nodeAddress);
  final networkSuffix = networkId & 0x00ffffff;
  final nodeSuffix =
      ((nodeAddress[2] & 0xff) << 16) |
      ((nodeAddress[3] & 0xff) << 8) |
      (nodeAddress[4] & 0xff);
  return 'zt${_hex6(networkSuffix)}${_hex6(nodeSuffix)}';
}

List<EmbeddedVirtualNetworkAddress> _parseManagedAddresses(Uint8List? data) {
  if (data == null) return const <EmbeddedVirtualNetworkAddress>[];
  final addresses = <EmbeddedVirtualNetworkAddress>[];
  var position = 0;
  while (position < data.length) {
    final parsed = _parseInetAddress(data, position);
    if (parsed == null) break;
    position += parsed.consumed;
    final address = parsed.address;
    if (address != null) {
      addresses.add(address);
    }
  }
  return List<EmbeddedVirtualNetworkAddress>.unmodifiable(addresses);
}

List<EmbeddedVirtualNetworkRoute> _parseManagedRoutes(Uint8List? data) {
  if (data == null) return const <EmbeddedVirtualNetworkRoute>[];
  final routes = <EmbeddedVirtualNetworkRoute>[];
  var position = 0;
  while (position < data.length) {
    final target = _parseInetAddress(data, position);
    if (target == null) break;
    position += target.consumed;

    final gateway = _parseInetAddress(data, position);
    if (gateway == null) break;
    position += gateway.consumed;

    if (position + 2 > data.length) break;
    final flags = (data[position] << 8) | data[position + 1];
    position += 2;

    final targetAddress = target.address;
    if (targetAddress != null) {
      routes.add(
        EmbeddedVirtualNetworkRoute(
          target: targetAddress,
          gateway: gateway.address,
          flags: flags,
        ),
      );
    }
  }
  return List<EmbeddedVirtualNetworkRoute>.unmodifiable(routes);
}

_ParsedInetAddress? _parseInetAddress(Uint8List data, int position) {
  if (position >= data.length) return null;
  final tag = data[position];
  if (tag == 0) {
    return const _ParsedInetAddress(null, 1);
  }
  if (tag == 4) {
    if (position + 7 > data.length) return null;
    return _ParsedInetAddress(
      EmbeddedVirtualNetworkAddress(
        family: EmbeddedVirtualNetworkAddressFamily.ipv4,
        bytes: data.sublist(position + 1, position + 5),
        prefixLength: (data[position + 5] << 8) | data[position + 6],
      ),
      7,
    );
  }
  if (tag == 6) {
    if (position + 19 > data.length) return null;
    return _ParsedInetAddress(
      EmbeddedVirtualNetworkAddress(
        family: EmbeddedVirtualNetworkAddressFamily.ipv6,
        bytes: data.sublist(position + 1, position + 17),
        prefixLength: (data[position + 17] << 8) | data[position + 18],
      ),
      19,
    );
  }
  return null;
}

class _ParsedInetAddress {
  const _ParsedInetAddress(this.address, this.consumed);

  final EmbeddedVirtualNetworkAddress? address;
  final int consumed;
}

class _ZeroTierDictionary {
  const _ZeroTierDictionary(this._entries);

  static _ZeroTierDictionary? tryParse(List<int> data) {
    try {
      return _ZeroTierDictionary(_parseEntries(data));
    } on FormatException {
      return null;
    }
  }

  final List<_ZeroTierDictionaryEntry> _entries;

  Uint8List? binary(String key) {
    for (final entry in _entries) {
      if (entry.key == key) return Uint8List.fromList(entry.value);
    }
    return null;
  }

  int? hexInt(String key) {
    final raw = binary(key);
    if (raw == null) return null;
    try {
      return int.tryParse(utf8.decode(raw), radix: 16);
    } on FormatException {
      return null;
    }
  }

  static List<_ZeroTierDictionaryEntry> _parseEntries(List<int> data) {
    final entries = <_ZeroTierDictionaryEntry>[];
    var position = 0;
    while (position < data.length) {
      while (position < data.length &&
          (data[position] == 0x0d || data[position] == 0x0a)) {
        position++;
      }
      if (position >= data.length) break;

      final keyStart = position;
      while (position < data.length &&
          data[position] != 0x3d &&
          data[position] != 0x0d &&
          data[position] != 0x0a) {
        position++;
      }
      if (position >= data.length || data[position] != 0x3d) {
        throw const FormatException('dictionary entry is missing =');
      }
      final key = utf8.decode(data.sublist(keyStart, position));
      position++;

      final value = <int>[];
      var escaped = false;
      while (position < data.length) {
        final byte = data[position];
        if (escaped) {
          escaped = false;
          value.add(switch (byte) {
            0x72 => 0x0d,
            0x6e => 0x0a,
            0x30 => 0,
            0x65 => 0x3d,
            _ => byte,
          });
          position++;
          continue;
        }
        if (byte == 0x5c) {
          escaped = true;
          position++;
          continue;
        }
        if (byte == 0x0d || byte == 0x0a) break;
        value.add(byte);
        position++;
      }

      entries.add(_ZeroTierDictionaryEntry(key, Uint8List.fromList(value)));

      if (position < data.length) {
        if (data[position] == 0x0d) {
          position++;
          if (position < data.length && data[position] == 0x0a) {
            position++;
          }
        } else {
          position++;
        }
      }
    }
    return entries;
  }
}

class _ZeroTierDictionaryEntry {
  const _ZeroTierDictionaryEntry(this.key, this.value);

  final String key;
  final Uint8List value;
}

String _ipv6AddressString(Uint8List bytes) {
  final groups = List<int>.generate(
    8,
    (index) => (bytes[index * 2] << 8) | bytes[index * 2 + 1],
    growable: false,
  );
  var bestStart = -1;
  var bestLength = 0;
  var index = 0;
  while (index < groups.length) {
    if (groups[index] != 0) {
      index++;
      continue;
    }
    final start = index;
    while (index < groups.length && groups[index] == 0) {
      index++;
    }
    final length = index - start;
    if (length > bestLength && length >= 2) {
      bestStart = start;
      bestLength = length;
    }
  }
  if (bestStart == -1) {
    return groups.map((group) => group.toRadixString(16)).join(':');
  }

  final before = groups
      .take(bestStart)
      .map((group) => group.toRadixString(16))
      .join(':');
  final after = groups
      .skip(bestStart + bestLength)
      .map((group) => group.toRadixString(16))
      .join(':');
  if (before.isEmpty && after.isEmpty) return '::';
  if (before.isEmpty) return '::$after';
  if (after.isEmpty) return '$before::';
  return '$before::$after';
}

String _hex6(int value) => value.toRadixString(16).padLeft(6, '0');

void _checkNodeAddress(List<int> nodeAddress) {
  if (nodeAddress.length != 5) {
    throw ArgumentError.value(
      nodeAddress.length,
      'nodeAddress.length',
      'must be 5',
    );
  }
  for (final byte in nodeAddress) {
    if (byte < 0 || byte > 255) {
      throw RangeError.range(byte, 0, 255, 'nodeAddress byte');
    }
  }
}
