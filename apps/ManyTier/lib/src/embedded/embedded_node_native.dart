import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'embedded_node.dart';

const bool embeddedNodeRuntimeSupported = true;
const String? embeddedNodeRuntimeUnsupportedReason = null;
const bool _isReleaseMode = bool.fromEnvironment('dart.vm.product');

EmbeddedNodeSession createNativeEmbeddedNodeSession({
  required String identitySecret,
  required Uint8List planet,
  int initialPacketId = 1,
  String? libraryPath,
}) {
  return EmbeddedNodeSession(
    NativeEmbeddedNodeDriver(
      identitySecret: identitySecret,
      planet: planet,
      initialPacketId: initialPacketId,
      libraryPath: libraryPath,
    ),
  );
}

final class _ManyTierNode extends ffi.Opaque {}

final class _FfiSocketAddress extends ffi.Struct {
  @ffi.Uint8()
  external int family;

  @ffi.Array(16)
  external ffi.Array<ffi.Uint8> address;

  @ffi.Uint16()
  external int port;
}

final class _FfiActionView extends ffi.Struct {
  @ffi.Int32()
  external int kind;

  external _FfiSocketAddress socketAddress;

  external ffi.Pointer<ffi.Uint8> dataPtr;

  @ffi.Size()
  external int dataLen;

  @ffi.Size()
  external int addressCount;

  @ffi.Uint64()
  external int networkId;

  @ffi.Uint64()
  external int packetId;

  @ffi.Uint64()
  external int typeId;

  @ffi.Array(5)
  external ffi.Array<ffi.Uint8> ztAddress;

  @ffi.Array(6)
  external ffi.Array<ffi.Uint8> srcMac;

  @ffi.Array(6)
  external ffi.Array<ffi.Uint8> destMac;

  @ffi.Uint16()
  external int ethertype;

  @ffi.Int16()
  external int utility;
}

typedef _NodeNewNative =
    ffi.Int32 Function(
      ffi.Pointer<ffi.Uint8>,
      ffi.Size,
      ffi.Pointer<ffi.Uint8>,
      ffi.Size,
      ffi.Uint64,
      ffi.Pointer<ffi.Pointer<_ManyTierNode>>,
    );
typedef _NodeNewDart =
    int Function(
      ffi.Pointer<ffi.Uint8>,
      int,
      ffi.Pointer<ffi.Uint8>,
      int,
      int,
      ffi.Pointer<ffi.Pointer<_ManyTierNode>>,
    );
typedef _NodeFreeNative = ffi.Void Function(ffi.Pointer<_ManyTierNode>);
typedef _NodeFreeDart = void Function(ffi.Pointer<_ManyTierNode>);
typedef _NodeAddressNative =
    ffi.Int32 Function(ffi.Pointer<_ManyTierNode>, ffi.Pointer<ffi.Uint8>);
typedef _NodeAddressDart =
    int Function(ffi.Pointer<_ManyTierNode>, ffi.Pointer<ffi.Uint8>);
typedef _CountCallNative =
    ffi.Int32 Function(
      ffi.Pointer<_ManyTierNode>,
      ffi.Uint64,
      ffi.Pointer<ffi.Size>,
    );
typedef _CountCallDart =
    int Function(ffi.Pointer<_ManyTierNode>, int, ffi.Pointer<ffi.Size>);
typedef _ReceiveNative =
    ffi.Int32 Function(
      ffi.Pointer<_ManyTierNode>,
      ffi.Pointer<ffi.Uint8>,
      ffi.Size,
      _FfiSocketAddress,
      ffi.Uint64,
      ffi.Pointer<ffi.Size>,
    );
typedef _ReceiveDart =
    int Function(
      ffi.Pointer<_ManyTierNode>,
      ffi.Pointer<ffi.Uint8>,
      int,
      _FfiSocketAddress,
      int,
      ffi.Pointer<ffi.Size>,
    );
typedef _SendWhoisNative =
    ffi.Int32 Function(
      ffi.Pointer<_ManyTierNode>,
      ffi.Pointer<ffi.Uint8>,
      ffi.Size,
      ffi.Uint64,
      ffi.Pointer<ffi.Size>,
    );
typedef _SendWhoisDart =
    int Function(
      ffi.Pointer<_ManyTierNode>,
      ffi.Pointer<ffi.Uint8>,
      int,
      int,
      ffi.Pointer<ffi.Size>,
    );
typedef _ActionCountNative =
    ffi.Int32 Function(ffi.Pointer<_ManyTierNode>, ffi.Pointer<ffi.Size>);
typedef _ActionCountDart =
    int Function(ffi.Pointer<_ManyTierNode>, ffi.Pointer<ffi.Size>);
typedef _ActionViewNative =
    ffi.Int32 Function(
      ffi.Pointer<_ManyTierNode>,
      ffi.Size,
      ffi.Pointer<_FfiActionView>,
    );
typedef _ActionViewDart =
    int Function(ffi.Pointer<_ManyTierNode>, int, ffi.Pointer<_FfiActionView>);
typedef _ClearActionsNative = ffi.Int32 Function(ffi.Pointer<_ManyTierNode>);
typedef _ClearActionsDart = int Function(ffi.Pointer<_ManyTierNode>);

class _ManyTierFfiBindings {
  _ManyTierFfiBindings(this.library)
    : nodeNew = library.lookupFunction<_NodeNewNative, _NodeNewDart>(
        'manytier_node_new',
      ),
      nodeFree = library.lookupFunction<_NodeFreeNative, _NodeFreeDart>(
        'manytier_node_free',
      ),
      nodeAddress = library
          .lookupFunction<_NodeAddressNative, _NodeAddressDart>(
            'manytier_node_address',
          ),
      nodeBootstrap = library.lookupFunction<_CountCallNative, _CountCallDart>(
        'manytier_node_bootstrap',
      ),
      nodeTick = library.lookupFunction<_CountCallNative, _CountCallDart>(
        'manytier_node_tick',
      ),
      nodeReceivePacket = library.lookupFunction<_ReceiveNative, _ReceiveDart>(
        'manytier_node_receive_packet',
      ),
      nodeSendWhois = library.lookupFunction<_SendWhoisNative, _SendWhoisDart>(
        'manytier_node_send_whois',
      ),
      nodeActionCount = library
          .lookupFunction<_ActionCountNative, _ActionCountDart>(
            'manytier_node_action_count',
          ),
      nodeActionView = library
          .lookupFunction<_ActionViewNative, _ActionViewDart>(
            'manytier_node_action_view',
          ),
      nodeClearActions = library
          .lookupFunction<_ClearActionsNative, _ClearActionsDart>(
            'manytier_node_clear_actions',
          ),
      nodeFreePointer = library.lookup<ffi.NativeFunction<_NodeFreeNative>>(
        'manytier_node_free',
      );

  final ffi.DynamicLibrary library;
  final _NodeNewDart nodeNew;
  final _NodeFreeDart nodeFree;
  final _NodeAddressDart nodeAddress;
  final _CountCallDart nodeBootstrap;
  final _CountCallDart nodeTick;
  final _ReceiveDart nodeReceivePacket;
  final _SendWhoisDart nodeSendWhois;
  final _ActionCountDart nodeActionCount;
  final _ActionViewDart nodeActionView;
  final _ClearActionsDart nodeClearActions;
  final ffi.Pointer<ffi.NativeFunction<_NodeFreeNative>> nodeFreePointer;
}

class NativeEmbeddedNodeDriver implements EmbeddedNodeDriver, ffi.Finalizable {
  NativeEmbeddedNodeDriver({
    required String identitySecret,
    required Uint8List planet,
    int initialPacketId = 1,
    String? libraryPath,
  }) : this._(
         _ManyTierFfiBindings(_openManyTierFfiLibrary(libraryPath)),
         identitySecret,
         planet,
         initialPacketId,
       );

  NativeEmbeddedNodeDriver._(
    this._bindings,
    String identitySecret,
    Uint8List planet,
    int initialPacketId,
  ) {
    _handle = _createNode(identitySecret, planet, initialPacketId);
    _finalizer = ffi.NativeFinalizer(_bindings.nodeFreePointer.cast());
    _finalizer.attach(this, _handle.cast(), detach: this);
  }

  final _ManyTierFfiBindings _bindings;
  late final ffi.Pointer<_ManyTierNode> _handle;
  late final ffi.NativeFinalizer _finalizer;
  bool _closed = false;

  @override
  Uint8List address() {
    _checkOpen();
    final out = calloc<ffi.Uint8>(5);
    try {
      _checkStatus(_bindings.nodeAddress(_handle, out), 'node address');
      return Uint8List.fromList(out.asTypedList(5));
    } finally {
      calloc.free(out);
    }
  }

  @override
  int bootstrap(int nowMs) {
    _checkOpen();
    return _countingCall(
      (out) => _bindings.nodeBootstrap(_handle, nowMs, out),
      'node bootstrap',
    );
  }

  @override
  int tick(int nowMs) {
    _checkOpen();
    return _countingCall(
      (out) => _bindings.nodeTick(_handle, nowMs, out),
      'node tick',
    );
  }

  @override
  int receivePacket(Uint8List packet, EmbeddedSocketAddress from, int nowMs) {
    _checkOpen();
    final packetPtr = calloc<ffi.Uint8>(packet.length);
    final out = calloc<ffi.Size>();
    final ffiFrom = calloc<_FfiSocketAddress>();
    try {
      packetPtr.asTypedList(packet.length).setAll(0, packet);
      _writeSocketAddress(ffiFrom.ref, from);
      _checkStatus(
        _bindings.nodeReceivePacket(
          _handle,
          packetPtr,
          packet.length,
          ffiFrom.ref,
          nowMs,
          out,
        ),
        'node receive packet',
      );
      return out.value;
    } finally {
      calloc.free(ffiFrom);
      calloc.free(out);
      calloc.free(packetPtr);
    }
  }

  @override
  int sendWhois(List<List<int>> addresses, int nowMs) {
    _checkOpen();
    final flattened = _flattenZtAddresses(addresses);
    final addressPtr = calloc<ffi.Uint8>(
      flattened.isEmpty ? 1 : flattened.length,
    );
    final out = calloc<ffi.Size>();
    try {
      if (flattened.isNotEmpty) {
        addressPtr.asTypedList(flattened.length).setAll(0, flattened);
      }
      _checkStatus(
        _bindings.nodeSendWhois(
          _handle,
          addressPtr,
          addresses.length,
          nowMs,
          out,
        ),
        'node send whois',
      );
      return out.value;
    } finally {
      calloc.free(out);
      calloc.free(addressPtr);
    }
  }

  @override
  int actionCount() {
    _checkOpen();
    return _countingCall(
      (out) => _bindings.nodeActionCount(_handle, out),
      'node action count',
    );
  }

  @override
  EmbeddedNodeAction actionAt(int index) {
    _checkOpen();
    final out = calloc<_FfiActionView>();
    try {
      _checkStatus(
        _bindings.nodeActionView(_handle, index, out),
        'node action view',
      );
      return _actionFromView(out.ref);
    } finally {
      calloc.free(out);
    }
  }

  @override
  void clearActions() {
    _checkOpen();
    _checkStatus(_bindings.nodeClearActions(_handle), 'node clear actions');
  }

  @override
  void close() {
    if (_closed) return;
    _closed = true;
    _finalizer.detach(this);
    _bindings.nodeFree(_handle);
  }

  ffi.Pointer<_ManyTierNode> _createNode(
    String identitySecret,
    Uint8List planet,
    int initialPacketId,
  ) {
    final identityBytes = Uint8List.fromList(utf8.encode(identitySecret));
    final identityPtr = calloc<ffi.Uint8>(identityBytes.length);
    final planetPtr = calloc<ffi.Uint8>(planet.length);
    final out = calloc<ffi.Pointer<_ManyTierNode>>();
    try {
      identityPtr.asTypedList(identityBytes.length).setAll(0, identityBytes);
      planetPtr.asTypedList(planet.length).setAll(0, planet);
      _checkStatus(
        _bindings.nodeNew(
          identityPtr,
          identityBytes.length,
          planetPtr,
          planet.length,
          initialPacketId,
          out,
        ),
        'node new',
      );
      return out.value;
    } finally {
      calloc.free(out);
      calloc.free(planetPtr);
      calloc.free(identityPtr);
    }
  }

  int _countingCall(
    int Function(ffi.Pointer<ffi.Size> out) call,
    String operation,
  ) {
    final out = calloc<ffi.Size>();
    try {
      _checkStatus(call(out), operation);
      return out.value;
    } finally {
      calloc.free(out);
    }
  }

  EmbeddedNodeAction _actionFromView(_FfiActionView view) {
    return EmbeddedNodeAction(
      kind: EmbeddedNodeActionKind.fromFfiCode(view.kind),
      socketAddress: _socketAddressFromFfi(view.socketAddress),
      data: _copyPointer(view.dataPtr, view.dataLen),
      addressCount: view.addressCount,
      networkId: view.networkId,
      packetId: view.packetId,
      typeId: view.typeId,
      ztAddress: _copyArray(view.ztAddress, 5),
      srcMac: _copyArray(view.srcMac, 6),
      destMac: _copyArray(view.destMac, 6),
      ethertype: view.ethertype,
      utility: view.utility,
    );
  }

  void _checkOpen() {
    if (_closed) {
      throw const EmbeddedNodeException('Embedded node driver is closed.');
    }
  }
}

ffi.DynamicLibrary _openManyTierFfiLibrary(String? libraryPath) {
  if (libraryPath != null) {
    return libraryPath.isEmpty
        ? ffi.DynamicLibrary.process()
        : ffi.DynamicLibrary.open(libraryPath);
  }

  final executableDir = File(Platform.resolvedExecutable).parent.path;
  final cwd = Directory.current.path;
  final names = switch (Platform.operatingSystem) {
    'macos' || 'ios' => const <String>['libzerotier_ffi.dylib'],
    'android' || 'linux' => const <String>['libzerotier_ffi.so'],
    'windows' => const <String>['zerotier_ffi.dll'],
    _ => throw UnsupportedError(
      'Embedded node runtime is not supported on ${Platform.operatingSystem}',
    ),
  };

  final attempted = <String>[];
  Object? lastError;
  final envPath = Platform.environment['MANYTIER_FFI_LIBRARY'];
  final candidates = <String>[
    if (envPath != null && envPath.trim().isNotEmpty) envPath.trim(),
    for (final name in names) ...<String>[
      '$executableDir/$name',
      '$executableDir/lib/$name',
      if (!_isReleaseMode) ...<String>[
        name,
        '$cwd/$name',
        '$cwd/lib/$name',
        '$cwd/target/debug/$name',
        '$cwd/target/release/$name',
        '$cwd/../../target/debug/$name',
        '$cwd/../../target/release/$name',
      ],
    ],
  ];

  for (final candidate in candidates) {
    try {
      return ffi.DynamicLibrary.open(candidate);
    } catch (error) {
      attempted.add(candidate);
      lastError = error;
    }
  }

  if (Platform.isMacOS || Platform.isIOS) {
    try {
      return ffi.DynamicLibrary.process();
    } catch (error) {
      attempted.add('<process image>');
      lastError = error;
    }
  }

  throw EmbeddedNodeException(
    'Failed to load zerotier-ffi native library.\n'
    'Current directory: ${Directory.current.path}\n'
    'Attempted paths:\n${attempted.map((path) => '- $path').join('\n')}\n'
    'Last error: $lastError',
  );
}

void _checkStatus(int status, String operation) {
  if (status == 0) return;
  final message = switch (status) {
    1 => 'null pointer',
    2 => 'invalid UTF-8',
    3 => 'invalid identity',
    4 => 'identity is missing its secret key',
    5 => 'invalid planet/moon world data',
    6 => 'invalid action index',
    7 => 'invalid socket address',
    8 => 'invalid ZeroTier address list',
    _ => 'unknown status $status',
  };
  throw EmbeddedNodeException('$operation failed: $message');
}

Uint8List _flattenZtAddresses(List<List<int>> addresses) {
  final out = Uint8List(addresses.length * 5);
  for (int addressIndex = 0; addressIndex < addresses.length; addressIndex++) {
    final address = addresses[addressIndex];
    if (address.length != 5) {
      throw ArgumentError.value(
        address.length,
        'addresses[$addressIndex].length',
        'must be 5',
      );
    }
    for (int byteIndex = 0; byteIndex < address.length; byteIndex++) {
      final byte = address[byteIndex];
      if (byte < 0 || byte > 255) {
        throw RangeError.range(
          byte,
          0,
          255,
          'addresses[$addressIndex][$byteIndex]',
        );
      }
      out[(addressIndex * 5) + byteIndex] = byte;
    }
  }
  return out;
}

void _writeSocketAddress(
  _FfiSocketAddress target,
  EmbeddedSocketAddress source,
) {
  target.family = source.family;
  target.port = source.port;
  for (int i = 0; i < 16; i++) {
    target.address[i] = source.address[i];
  }
}

EmbeddedSocketAddress? _socketAddressFromFfi(_FfiSocketAddress source) {
  if (source.family != 4 && source.family != 6) return null;
  return EmbeddedSocketAddress(
    family: source.family,
    address: _copyArray(source.address, 16),
    port: source.port,
  );
}

List<int> _copyPointer(ffi.Pointer<ffi.Uint8> pointer, int length) {
  if (pointer == ffi.nullptr || length == 0) return const <int>[];
  return Uint8List.fromList(pointer.asTypedList(length));
}

List<int> _copyArray(ffi.Array<ffi.Uint8> array, int length) {
  return List<int>.unmodifiable(
    List<int>.generate(length, (index) => array[index], growable: false),
  );
}
