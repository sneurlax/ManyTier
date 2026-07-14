import 'dart:async';

import 'package:flutter/services.dart';

import 'embedded_node.dart';
import 'embedded_virtual_network.dart';

class EmbeddedVirtualNetworkSupport {
  const EmbeddedVirtualNetworkSupport({
    required this.isSupported,
    this.reason,
    this.platform,
    this.details = const <String, Object?>{},
  });

  factory EmbeddedVirtualNetworkSupport.fromNativeResult(Object? result) {
    if (result is bool) {
      return EmbeddedVirtualNetworkSupport(isSupported: result);
    }
    final map = _stringKeyedMap(result);
    return EmbeddedVirtualNetworkSupport(
      isSupported: map['supported'] == true,
      reason: _nonEmptyString(map['reason']),
      platform: _nonEmptyString(map['platform']),
      details: map,
    );
  }

  final bool isSupported;
  final String? reason;
  final String? platform;
  final Map<String, Object?> details;
}

class MethodChannelEmbeddedVirtualNetworkFactory
    implements EmbeddedVirtualNetworkFactory {
  MethodChannelEmbeddedVirtualNetworkFactory({
    MethodChannel? channel,
    this.supported = true,
    this.unsupportedReason,
  }) : _channel = channel ?? defaultChannel {
    _channel.setMethodCallHandler(handleNativeMethodCall);
  }

  static const MethodChannel defaultChannel = MethodChannel(
    'com.manytier.native/virtual_networks',
  );

  final MethodChannel _channel;
  final bool supported;

  @override
  final String? unsupportedReason;

  final Map<String, _MethodChannelEmbeddedVirtualNetworkInterface> _interfaces =
      <String, _MethodChannelEmbeddedVirtualNetworkInterface>{};

  @override
  bool get isSupported => supported;

  Future<EmbeddedVirtualNetworkSupport> checkSupport() async {
    if (!supported) {
      return EmbeddedVirtualNetworkSupport(
        isSupported: false,
        reason:
            unsupportedReason ??
            'Native virtual network devices are unavailable.',
      );
    }
    try {
      final result = await _channel.invokeMethod<Object?>(
        'virtualNetworkSupport',
      );
      return EmbeddedVirtualNetworkSupport.fromNativeResult(result);
    } on MissingPluginException {
      return const EmbeddedVirtualNetworkSupport(
        isSupported: false,
        reason: 'Native virtual network handler is unavailable.',
      );
    } on PlatformException catch (e) {
      return EmbeddedVirtualNetworkSupport(
        isSupported: false,
        reason:
            e.message ??
            'Native virtual network support probe failed: ${e.code}',
        details: <String, Object?>{
          'code': e.code,
          if (e.details != null) 'details': e.details,
        },
      );
    }
  }

  @override
  Future<EmbeddedVirtualNetworkInterface> create(
    EmbeddedVirtualNetworkConfig config,
  ) async {
    if (!supported) {
      throw EmbeddedNodeException(
        unsupportedReason ?? 'Native virtual network devices are unavailable.',
      );
    }
    final result = await _invokeCreate(config);
    final interface = _MethodChannelEmbeddedVirtualNetworkInterface(
      channel: _channel,
      interfaceId: result.interfaceId,
      networkId: config.networkId,
      networkIdHex: _networkIdHex(config.networkId),
      onClose: _interfaces.remove,
    );
    _interfaces[interface.interfaceId] = interface;
    return interface;
  }

  Future<Object?> handleNativeMethodCall(MethodCall call) async {
    return switch (call.method) {
      'virtualPacket' => _handleVirtualPacket(call.arguments),
      _ => throw MissingPluginException(
        'Unknown virtual network method ${call.method}',
      ),
    };
  }

  Future<void> dispose() async {
    _channel.setMethodCallHandler(null);
    final interfaces = List<_MethodChannelEmbeddedVirtualNetworkInterface>.from(
      _interfaces.values,
    );
    _interfaces.clear();
    for (final interface in interfaces) {
      await interface.close();
    }
  }

  Future<_CreateVirtualNetworkResult> _invokeCreate(
    EmbeddedVirtualNetworkConfig config,
  ) async {
    try {
      final result = await _channel.invokeMethod<Object?>(
        'createVirtualNetwork',
        _configArguments(config),
      );
      return _CreateVirtualNetworkResult.fromNativeResult(
        result,
        fallbackInterfaceId: config.interfaceName,
      );
    } on MissingPluginException {
      throw const EmbeddedNodeException(
        'Native virtual network handler is unavailable.',
      );
    } on PlatformException catch (e) {
      throw EmbeddedNodeException(
        e.message ?? 'Native virtual network creation failed: ${e.code}',
      );
    }
  }

  Object? _handleVirtualPacket(Object? arguments) {
    final args = _asMap(arguments);
    final interfaceId = args['interfaceId'] as String?;
    if (interfaceId == null) return null;
    final interface = _interfaces[interfaceId];
    if (interface == null) return null;
    final packet = _asUint8List(args['packet']);
    if (packet == null) return null;
    interface.addNativePacket(packet);
    return null;
  }
}

class _MethodChannelEmbeddedVirtualNetworkInterface
    implements EmbeddedVirtualNetworkInterface {
  _MethodChannelEmbeddedVirtualNetworkInterface({
    required MethodChannel channel,
    required this.interfaceId,
    required this.networkId,
    required this.networkIdHex,
    required void Function(String interfaceId) onClose,
  }) : _channel = channel,
       _onClose = onClose;

  final MethodChannel _channel;
  final String interfaceId;
  final String networkIdHex;
  final void Function(String interfaceId) _onClose;
  final StreamController<Uint8List> _packets =
      StreamController<Uint8List>.broadcast();
  bool _closed = false;

  @override
  final int networkId;

  @override
  Stream<Uint8List> get packets => _packets.stream;

  @override
  Future<void> write(Uint8List packet) async {
    if (_closed) return;
    await _channel.invokeMethod<void>('writeVirtualPacket', <String, Object?>{
      'interfaceId': interfaceId,
      'networkIdHex': networkIdHex,
      'packet': Uint8List.fromList(packet),
    });
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _onClose(interfaceId);
    try {
      await _channel.invokeMethod<void>(
        'closeVirtualNetwork',
        <String, Object?>{
          'interfaceId': interfaceId,
          'networkIdHex': networkIdHex,
        },
      );
    } on MissingPluginException {
      // The native side may disappear during app teardown.
    } finally {
      await _packets.close();
    }
  }

  void addNativePacket(Uint8List packet) {
    if (_closed) return;
    _packets.add(Uint8List.fromList(packet));
  }
}

class _CreateVirtualNetworkResult {
  const _CreateVirtualNetworkResult({required this.interfaceId});

  factory _CreateVirtualNetworkResult.fromNativeResult(
    Object? result, {
    required String fallbackInterfaceId,
  }) {
    if (result is String && result.isNotEmpty) {
      return _CreateVirtualNetworkResult(interfaceId: result);
    }
    final map = _asMap(result);
    final interfaceId = map['interfaceId'];
    if (interfaceId is String && interfaceId.isNotEmpty) {
      return _CreateVirtualNetworkResult(interfaceId: interfaceId);
    }
    return _CreateVirtualNetworkResult(interfaceId: fallbackInterfaceId);
  }

  final String interfaceId;
}

Map<Object?, Object?> _asMap(Object? value) {
  if (value is Map<Object?, Object?>) return value;
  if (value is Map) return Map<Object?, Object?>.from(value);
  return const <Object?, Object?>{};
}

Map<String, Object?> _stringKeyedMap(Object? value) {
  final map = _asMap(value);
  return <String, Object?>{
    for (final entry in map.entries)
      if (entry.key is String) entry.key as String: entry.value,
  };
}

String? _nonEmptyString(Object? value) {
  if (value is! String || value.isEmpty) return null;
  return value;
}

Uint8List? _asUint8List(Object? value) {
  if (value is Uint8List) return Uint8List.fromList(value);
  if (value is List<int>) return Uint8List.fromList(value);
  return null;
}

Map<String, Object?> _configArguments(EmbeddedVirtualNetworkConfig config) {
  return <String, Object?>{
    'networkIdHex': _networkIdHex(config.networkId),
    'interfaceName': config.interfaceName,
    'nodeAddress': Uint8List.fromList(config.nodeAddress),
    'dictData': Uint8List.fromList(config.dictData),
    'mtu': config.settings.mtu,
    'managedAddresses': config.settings.managedAddresses
        .map(_addressArguments)
        .toList(growable: false),
    'routes': config.settings.routes
        .map(_routeArguments)
        .toList(growable: false),
  };
}

Map<String, Object?> _addressArguments(EmbeddedVirtualNetworkAddress address) {
  return <String, Object?>{
    'family': switch (address.family) {
      EmbeddedVirtualNetworkAddressFamily.ipv4 => 'ipv4',
      EmbeddedVirtualNetworkAddressFamily.ipv6 => 'ipv6',
    },
    'address': address.address,
    'prefixLength': address.prefixLength,
    'bytes': Uint8List.fromList(address.bytes),
  };
}

Map<String, Object?> _routeArguments(EmbeddedVirtualNetworkRoute route) {
  return <String, Object?>{
    'target': _addressArguments(route.target),
    'gateway': route.gateway == null ? null : _addressArguments(route.gateway!),
    'flags': route.flags,
  };
}

String _networkIdHex(int networkId) {
  return BigInt.from(
    networkId,
  ).toUnsigned(64).toRadixString(16).padLeft(16, '0');
}
