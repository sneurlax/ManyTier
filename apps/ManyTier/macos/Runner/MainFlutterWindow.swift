import Cocoa
import FlutterMacOS
import NetworkExtension

let macOSVirtualNetworkUnsupportedMessage =
  "macOS virtual network devices require a Network Extension packet tunnel handler, which is not implemented yet."

class MainFlutterWindow: NSWindow {
  private var virtualNetworkChannel: ManyTierVirtualNetworkChannel?

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
    virtualNetworkChannel = ManyTierVirtualNetworkChannel(
      messenger: flutterViewController.engine.binaryMessenger,
      adapter: PacketTunnelVirtualNetworkAdapter()
    )

    super.awakeFromNib()
  }
}

final class ManyTierVirtualNetworkChannel {
  private let channel: FlutterMethodChannel
  private let adapter: ManyTierVirtualNetworkAdapter

  init(
    messenger: FlutterBinaryMessenger,
    adapter: ManyTierVirtualNetworkAdapter = UnsupportedVirtualNetworkAdapter()
  ) {
    self.adapter = adapter
    channel = FlutterMethodChannel(
      name: "com.manytier.native/virtual_networks",
      binaryMessenger: messenger
    )
    channel.setMethodCallHandler(handle)
    adapter.onVirtualPacket = { [weak self] packet in
      self?.emitVirtualPacket(packet)
    }
  }

  private func handle(call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "virtualNetworkSupport":
      result(adapter.supportDetails)
    case "createVirtualNetwork":
      let request = VirtualNetworkRequest(arguments: call.arguments)
      adapter.createVirtualNetwork(request) { createResult in
        result(flutterResult(from: createResult))
      }
    case "writeVirtualPacket":
      adapter.writeVirtualPacket(VirtualNetworkPacket(arguments: call.arguments)) { writeResult in
        result(flutterResult(from: writeResult))
      }
    case "closeVirtualNetwork":
      adapter.closeVirtualNetwork(VirtualNetworkCloseRequest(arguments: call.arguments))
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func emitVirtualPacket(_ packet: VirtualNetworkPacket) {
    let arguments = packet.channelArguments
    DispatchQueue.main.async { [channel] in
      channel.invokeMethod("virtualPacket", arguments: arguments)
    }
  }
}

protocol ManyTierVirtualNetworkAdapter: AnyObject {
  var onVirtualPacket: ((VirtualNetworkPacket) -> Void)? { get set }
  var supportDetails: [String: Any] { get }

  func createVirtualNetwork(
    _ request: VirtualNetworkRequest,
    completion: @escaping (Result<Any?, Error>) -> Void
  )
  func writeVirtualPacket(
    _ packet: VirtualNetworkPacket,
    completion: @escaping (Result<Void, Error>) -> Void
  )
  func closeVirtualNetwork(_ request: VirtualNetworkCloseRequest)
}

struct VirtualNetworkAdapterError: Error {
  let code: String
  let message: String
  let details: Any?

  var flutterError: FlutterError {
    FlutterError(code: code, message: message, details: details)
  }
}

func flutterResult(from result: Result<Any?, Error>) -> Any? {
  switch result {
  case .success(let value):
    return value
  case .failure(let error as VirtualNetworkAdapterError):
    return error.flutterError
  case .failure(let error):
    return FlutterError(code: "native_error", message: "\(error)", details: nil)
  }
}

func flutterResult(from result: Result<Void, Error>) -> Any? {
  switch result {
  case .success:
    return nil
  case .failure(let error as VirtualNetworkAdapterError):
    return error.flutterError
  case .failure(let error):
    return FlutterError(code: "native_error", message: "\(error)", details: nil)
  }
}

final class UnsupportedVirtualNetworkAdapter: ManyTierVirtualNetworkAdapter {
  var onVirtualPacket: ((VirtualNetworkPacket) -> Void)?

  var supportDetails: [String: Any] {
    [
      "supported": false,
      "platform": "macos",
      "reason": macOSVirtualNetworkUnsupportedMessage,
      "requiredHandler": "NetworkExtension packet tunnel provider",
    ]
  }

  func createVirtualNetwork(
    _ request: VirtualNetworkRequest,
    completion: @escaping (Result<Any?, Error>) -> Void
  ) {
    completion(.failure(VirtualNetworkAdapterError(
      code: "unsupported",
      message: macOSVirtualNetworkUnsupportedMessage,
      details: request.details
    )))
  }

  func writeVirtualPacket(
    _ packet: VirtualNetworkPacket,
    completion: @escaping (Result<Void, Error>) -> Void
  ) {
    completion(.failure(VirtualNetworkAdapterError(
      code: "not_available",
      message: "No macOS virtual network interface is active.",
      details: packet.details
    )))
  }

  func closeVirtualNetwork(_ request: VirtualNetworkCloseRequest) {}
}

struct PacketTunnelConfiguration {
  let providerBundleIdentifier: String?

  init(providerBundleIdentifier: String?) {
    self.providerBundleIdentifier = providerBundleIdentifier
  }

  init(bundle: Bundle = .main) {
    providerBundleIdentifier = bundle.object(
      forInfoDictionaryKey: "ManyTierPacketTunnelProviderBundleIdentifier"
    ) as? String
  }

  var hasProviderBundleIdentifier: Bool {
    guard let providerBundleIdentifier else {
      return false
    }
    return !providerBundleIdentifier.isEmpty
  }
}

protocol PacketTunnelManagerStore {
  func loadManager(
    providerBundleIdentifier: String,
    completion: @escaping (Result<PacketTunnelManager, Error>) -> Void
  )
}

protocol PacketTunnelManager: AnyObject {
  func start(
    options: [String: NSObject],
    completion: @escaping (Error?) -> Void
  )
  func sendProviderMessage(
    _ data: Data,
    completion: @escaping (Result<Data?, Error>) -> Void
  )
  func stop()
}

protocol PacketTunnelDrainTimer: AnyObject {
  func cancel()
}

protocol PacketTunnelDrainScheduler {
  func scheduleRepeating(
    interval: TimeInterval,
    fire: @escaping () -> Void
  ) -> PacketTunnelDrainTimer
}

final class DispatchPacketTunnelDrainScheduler: PacketTunnelDrainScheduler {
  func scheduleRepeating(
    interval: TimeInterval,
    fire: @escaping () -> Void
  ) -> PacketTunnelDrainTimer {
    DispatchPacketTunnelDrainTimer(interval: interval, fire: fire)
  }
}

private final class DispatchPacketTunnelDrainTimer: PacketTunnelDrainTimer {
  init(interval: TimeInterval, fire: @escaping () -> Void) {
    let interval = packetTunnelDrainDispatchInterval(interval)
    let timer = DispatchSource.makeTimerSource(queue: .main)
    timer.schedule(
      deadline: .now() + interval,
      repeating: interval,
      leeway: packetTunnelDrainDispatchLeeway(interval)
    )
    timer.setEventHandler(handler: fire)
    timer.resume()
    self.timer = timer
  }

  private let timer: DispatchSourceTimer
  private var isCancelled = false

  func cancel() {
    guard !isCancelled else {
      return
    }
    isCancelled = true
    timer.setEventHandler(handler: {})
    timer.cancel()
  }

  deinit {
    cancel()
  }
}

private func packetTunnelDrainDispatchInterval(_ interval: TimeInterval) -> DispatchTimeInterval {
  .milliseconds(max(1, Int(interval * 1000)))
}

private func packetTunnelDrainDispatchLeeway(_ interval: DispatchTimeInterval) -> DispatchTimeInterval {
  switch interval {
  case .milliseconds(let milliseconds):
    return .milliseconds(max(1, milliseconds / 2))
  default:
    return .milliseconds(25)
  }
}

final class NetworkExtensionPacketTunnelManagerStore: PacketTunnelManagerStore {
  func loadManager(
    providerBundleIdentifier: String,
    completion: @escaping (Result<PacketTunnelManager, Error>) -> Void
  ) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error {
        completion(.failure(error))
        return
      }

      let manager = managers?.first { manager in
        let tunnel = manager.protocolConfiguration as? NETunnelProviderProtocol
        return tunnel?.providerBundleIdentifier == providerBundleIdentifier
      } ?? NETunnelProviderManager()

      let tunnel = NETunnelProviderProtocol()
      tunnel.providerBundleIdentifier = providerBundleIdentifier
      tunnel.serverAddress = "ManyTier Embedded Network"
      tunnel.providerConfiguration = [:]
      manager.localizedDescription = "ManyTier Embedded Network"
      manager.protocolConfiguration = tunnel
      manager.isEnabled = true
      manager.saveToPreferences { error in
        if let error {
          completion(.failure(error))
          return
        }
        manager.loadFromPreferences { error in
          if let error {
            completion(.failure(error))
            return
          }
          completion(.success(NetworkExtensionPacketTunnelManager(manager: manager)))
        }
      }
    }
  }
}

final class NetworkExtensionPacketTunnelManager: PacketTunnelManager {
  init(manager: NETunnelProviderManager) {
    self.manager = manager
  }

  private let manager: NETunnelProviderManager

  func start(
    options: [String: NSObject],
    completion: @escaping (Error?) -> Void
  ) {
    do {
      try manager.connection.startVPNTunnel(options: options)
      completion(nil)
    } catch {
      completion(error)
    }
  }

  func sendProviderMessage(
    _ data: Data,
    completion: @escaping (Result<Data?, Error>) -> Void
  ) {
    guard let session = manager.connection as? NETunnelProviderSession else {
      completion(.failure(VirtualNetworkAdapterError(
        code: "not_available",
        message: "No macOS virtual network interface is active.",
        details: nil
      )))
      return
    }
    do {
      try session.sendProviderMessage(data) { response in
        completion(.success(response))
      }
    } catch {
      completion(.failure(error))
    }
  }

  func stop() {
    manager.connection.stopVPNTunnel()
  }
}

final class PacketTunnelVirtualNetworkAdapter: ManyTierVirtualNetworkAdapter {
  init(
    configuration: PacketTunnelConfiguration = PacketTunnelConfiguration(),
    store: PacketTunnelManagerStore = NetworkExtensionPacketTunnelManagerStore(),
    drainScheduler: PacketTunnelDrainScheduler = DispatchPacketTunnelDrainScheduler(),
    drainInterval: TimeInterval = 0.05
  ) {
    self.configuration = configuration
    self.store = store
    self.drainScheduler = drainScheduler
    self.drainInterval = drainInterval
  }

  var onVirtualPacket: ((VirtualNetworkPacket) -> Void)?

  private let configuration: PacketTunnelConfiguration
  private let store: PacketTunnelManagerStore
  private let drainScheduler: PacketTunnelDrainScheduler
  private let drainInterval: TimeInterval
  private var activeInterfaces: [String: ActivePacketTunnelVirtualNetwork] = [:]

  var supportDetails: [String: Any] {
    guard configuration.hasProviderBundleIdentifier,
          let providerBundleIdentifier = configuration.providerBundleIdentifier else {
      return [
        "supported": false,
        "platform": "macos",
        "reason": "ManyTierPacketTunnelProviderBundleIdentifier is not configured.",
        "requiredHandler": "NetworkExtension packet tunnel provider",
      ]
    }
    return [
      "supported": true,
      "platform": "macos",
      "providerBundleIdentifier": providerBundleIdentifier,
      "requiredHandler": "NetworkExtension packet tunnel provider",
    ]
  }

  func createVirtualNetwork(
    _ request: VirtualNetworkRequest,
    completion: @escaping (Result<Any?, Error>) -> Void
  ) {
    guard configuration.hasProviderBundleIdentifier,
          let providerBundleIdentifier = configuration.providerBundleIdentifier else {
      completion(.failure(VirtualNetworkAdapterError(
        code: "unsupported",
        message: "ManyTierPacketTunnelProviderBundleIdentifier is not configured.",
        details: request.details
      )))
      return
    }
    guard let interfaceId = request.interfaceName, !interfaceId.isEmpty else {
      completion(.failure(VirtualNetworkAdapterError(
        code: "invalid_request",
        message: "Virtual network interfaceName is required.",
        details: request.details
      )))
      return
    }

    store.loadManager(providerBundleIdentifier: providerBundleIdentifier) { [weak self] result in
      switch result {
      case .failure(let error):
        completion(.failure(VirtualNetworkAdapterError(
          code: "manager_unavailable",
          message: "\(error)",
          details: request.details
        )))
      case .success(let manager):
        do {
          let message = try PacketTunnelProviderMessage.create(request).data()
          manager.start(options: ["manytierMessage": message as NSData]) { error in
            if let error {
              completion(.failure(VirtualNetworkAdapterError(
                code: "start_failed",
                message: "\(error)",
                details: request.details
              )))
              return
            }
            guard let self else {
              completion(.success(["interfaceId": interfaceId]))
              return
            }
            let activeInterface = ActivePacketTunnelVirtualNetwork(
              interfaceId: interfaceId,
              networkIdHex: request.networkIdHex,
              manager: manager
            )
            self.activeInterfaces[interfaceId] = activeInterface
            self.startDrainPolling(activeInterface)
            completion(.success(["interfaceId": interfaceId]))
          }
        } catch {
          completion(.failure(VirtualNetworkAdapterError(
            code: "message_encode_failed",
            message: "\(error)",
            details: request.details
          )))
        }
      }
    }
  }

  func writeVirtualPacket(
    _ packet: VirtualNetworkPacket,
    completion: @escaping (Result<Void, Error>) -> Void
  ) {
    guard let interfaceId = packet.interfaceId,
          let activeInterface = activeInterfaces[interfaceId] else {
      completion(.failure(VirtualNetworkAdapterError(
        code: "not_available",
        message: "No macOS virtual network interface is active.",
        details: packet.details
      )))
      return
    }
    do {
      let message = try PacketTunnelProviderMessage.write(packet).data()
      activeInterface.manager.sendProviderMessage(message) { result in
        switch result {
        case .success:
          completion(.success(()))
        case .failure(let error):
          completion(.failure(VirtualNetworkAdapterError(
            code: "write_failed",
            message: "\(error)",
            details: packet.details
          )))
        }
      }
    } catch {
      completion(.failure(VirtualNetworkAdapterError(
        code: "message_encode_failed",
        message: "\(error)",
        details: packet.details
      )))
    }
  }

  func closeVirtualNetwork(_ request: VirtualNetworkCloseRequest) {
    guard let interfaceId = request.interfaceId else {
      return
    }
    let activeInterface = activeInterfaces.removeValue(forKey: interfaceId)
    activeInterface?.drainTimer?.cancel()
    activeInterface?.manager.stop()
  }

  private func startDrainPolling(_ activeInterface: ActivePacketTunnelVirtualNetwork) {
    activeInterface.drainTimer = drainScheduler.scheduleRepeating(
      interval: drainInterval
    ) { [weak self, weak activeInterface] in
      guard let activeInterface else {
        return
      }
      self?.drainProviderPackets(activeInterface)
    }
  }

  private func drainProviderPackets(_ activeInterface: ActivePacketTunnelVirtualNetwork) {
    guard activeInterfaces[activeInterface.interfaceId] === activeInterface,
          !activeInterface.drainInFlight else {
      return
    }
    activeInterface.drainInFlight = true

    let message: Data
    do {
      message = try PacketTunnelProviderMessage.drain(
        interfaceId: activeInterface.interfaceId,
        networkIdHex: activeInterface.networkIdHex
      ).data()
    } catch {
      activeInterface.drainInFlight = false
      return
    }

    activeInterface.manager.sendProviderMessage(message) { [weak self, weak activeInterface] result in
      DispatchQueue.main.async {
        guard let self, let activeInterface else {
          return
        }
        self.finishDrain(activeInterface, result: result)
      }
    }
  }

  private func finishDrain(
    _ activeInterface: ActivePacketTunnelVirtualNetwork,
    result: Result<Data?, Error>
  ) {
    activeInterface.drainInFlight = false
    guard activeInterfaces[activeInterface.interfaceId] === activeInterface else {
      return
    }
    guard case .success(let data?) = result,
          let response = try? PacketTunnelDrainResponse(data: data),
          response.interfaceId == activeInterface.interfaceId else {
      return
    }
    let networkIdHex = response.networkIdHex ?? activeInterface.networkIdHex
    for packet in response.packets {
      onVirtualPacket?(VirtualNetworkPacket(
        interfaceId: response.interfaceId,
        networkIdHex: networkIdHex,
        packet: packet.packet
      ))
    }
  }
}

private final class ActivePacketTunnelVirtualNetwork {
  init(
    interfaceId: String,
    networkIdHex: String?,
    manager: PacketTunnelManager
  ) {
    self.interfaceId = interfaceId
    self.networkIdHex = networkIdHex
    self.manager = manager
  }

  let interfaceId: String
  let networkIdHex: String?
  let manager: PacketTunnelManager
  var drainTimer: PacketTunnelDrainTimer?
  var drainInFlight = false
}

extension PacketTunnelProviderMessage {
  static func create(_ request: VirtualNetworkRequest) -> PacketTunnelProviderMessage {
    PacketTunnelProviderMessage(type: "create", payload: request.packetTunnelPayload)
  }

  static func write(_ packet: VirtualNetworkPacket) -> PacketTunnelProviderMessage {
    PacketTunnelProviderMessage(type: "write", payload: packet.packetTunnelPayload)
  }

  static func drain(interfaceId: String, networkIdHex: String?) -> PacketTunnelProviderMessage {
    PacketTunnelProviderMessage(type: "drain", payload: [
      "interfaceId": interfaceId,
      "networkIdHex": manyTierJsonValue(networkIdHex),
    ])
  }
}

struct VirtualNetworkRequest {
  let networkIdHex: String?
  let interfaceName: String?
  let nodeAddress: [UInt8]
  let dictData: [UInt8]
  let mtu: Int?
  let managedAddresses: [VirtualNetworkAddress]
  let routes: [VirtualNetworkRoute]

  init(arguments: Any?) {
    guard let args = arguments as? [String: Any] else {
      networkIdHex = nil
      interfaceName = nil
      nodeAddress = []
      dictData = []
      mtu = nil
      managedAddresses = []
      routes = []
      return
    }
    networkIdHex = args["networkIdHex"] as? String
    interfaceName = args["interfaceName"] as? String
    nodeAddress = manyTierBytes(args["nodeAddress"])
    dictData = manyTierBytes(args["dictData"])
    mtu = manyTierInt(args["mtu"])
    managedAddresses = VirtualNetworkAddress.list(from: args["managedAddresses"])
    routes = VirtualNetworkRoute.list(from: args["routes"])
  }

  var details: [String: Any] {
    var details: [String: Any] = ["platform": "macos"]
    if let networkIdHex {
      details["networkIdHex"] = networkIdHex
    }
    if let interfaceName {
      details["interfaceName"] = interfaceName
    }
    if let mtu {
      details["mtu"] = mtu
    }
    details["nodeAddressLength"] = nodeAddress.count
    details["dictDataLength"] = dictData.count
    details["managedAddressCount"] = managedAddresses.count
    details["routeCount"] = routes.count
    return details
  }

  var packetTunnelPayload: [String: Any] {
    [
      "networkIdHex": networkIdHex ?? "",
      "interfaceName": interfaceName ?? "",
      "nodeAddress": manyTierIntBytes(nodeAddress),
      "dictData": manyTierIntBytes(dictData),
      "mtu": manyTierJsonValue(mtu),
      "managedAddresses": managedAddresses.map(\.packetTunnelPayload),
      "routes": routes.map(\.packetTunnelPayload),
    ]
  }
}

struct VirtualNetworkAddress: Equatable {
  let family: String?
  let address: String?
  let prefixLength: Int?
  let bytes: [UInt8]

  init?(arguments: Any?) {
    guard let args = arguments as? [String: Any] else {
      return nil
    }
    family = args["family"] as? String
    address = args["address"] as? String
    prefixLength = manyTierInt(args["prefixLength"])
    bytes = manyTierBytes(args["bytes"])
  }

  static func list(from value: Any?) -> [VirtualNetworkAddress] {
    guard let values = value as? [Any] else {
      return []
    }
    return values.compactMap(VirtualNetworkAddress.init(arguments:))
  }

  var packetTunnelPayload: [String: Any] {
    [
      "family": family ?? "",
      "address": address ?? "",
      "prefixLength": manyTierJsonValue(prefixLength),
      "bytes": manyTierIntBytes(bytes),
    ]
  }
}

struct VirtualNetworkRoute: Equatable {
  let target: VirtualNetworkAddress
  let gateway: VirtualNetworkAddress?
  let flags: Int?

  init?(arguments: Any?) {
    guard let args = arguments as? [String: Any],
          let target = VirtualNetworkAddress(arguments: args["target"]) else {
      return nil
    }
    self.target = target
    gateway = VirtualNetworkAddress(arguments: args["gateway"])
    flags = manyTierInt(args["flags"])
  }

  static func list(from value: Any?) -> [VirtualNetworkRoute] {
    guard let values = value as? [Any] else {
      return []
    }
    return values.compactMap(VirtualNetworkRoute.init(arguments:))
  }

  var packetTunnelPayload: [String: Any] {
    [
      "target": target.packetTunnelPayload,
      "gateway": manyTierJsonValue(gateway?.packetTunnelPayload),
      "flags": manyTierJsonValue(flags),
    ]
  }
}

struct VirtualNetworkPacket {
  let interfaceId: String?
  let networkIdHex: String?
  let packet: [UInt8]

  init(interfaceId: String, networkIdHex: String?, packet: [UInt8]) {
    self.interfaceId = interfaceId
    self.networkIdHex = networkIdHex
    self.packet = packet
  }

  init(arguments: Any?) {
    guard let args = arguments as? [String: Any] else {
      interfaceId = nil
      networkIdHex = nil
      packet = []
      return
    }
    interfaceId = args["interfaceId"] as? String
    networkIdHex = args["networkIdHex"] as? String
    packet = manyTierBytes(args["packet"])
  }

  var details: [String: Any] {
    var details: [String: Any] = ["platform": "macos"]
    if let interfaceId {
      details["interfaceId"] = interfaceId
    }
    if let networkIdHex {
      details["networkIdHex"] = networkIdHex
    }
    details["packetLength"] = packet.count
    return details
  }

  var packetTunnelPayload: [String: Any] {
    [
      "interfaceId": interfaceId ?? "",
      "networkIdHex": networkIdHex ?? "",
      "packet": manyTierIntBytes(packet),
    ]
  }

  var channelArguments: [String: Any] {
    [
      "interfaceId": interfaceId ?? "",
      "networkIdHex": manyTierJsonValue(networkIdHex),
      "packet": FlutterStandardTypedData(bytes: Data(packet)),
    ]
  }
}

struct VirtualNetworkCloseRequest {
  let interfaceId: String?
  let networkIdHex: String?

  init(arguments: Any?) {
    guard let args = arguments as? [String: Any] else {
      interfaceId = nil
      networkIdHex = nil
      return
    }
    interfaceId = args["interfaceId"] as? String
    networkIdHex = args["networkIdHex"] as? String
  }
}

func manyTierBytes(_ value: Any?) -> [UInt8] {
  if let typedData = value as? FlutterStandardTypedData {
    return [UInt8](typedData.data)
  }
  if let data = value as? Data {
    return [UInt8](data)
  }
  if let bytes = value as? [UInt8] {
    return bytes
  }
  if let numbers = value as? [NSNumber] {
    return numbers.map { UInt8(truncating: $0) }
  }
  if let numbers = value as? [Int] {
    return numbers.map { UInt8(truncatingIfNeeded: $0) }
  }
  return []
}

func manyTierInt(_ value: Any?) -> Int? {
  if let int = value as? Int {
    return int
  }
  if let number = value as? NSNumber {
    return number.intValue
  }
  return nil
}

func manyTierIntBytes(_ bytes: [UInt8]) -> [Int] {
  bytes.map(Int.init)
}

func manyTierJsonValue(_ value: Any?) -> Any {
  value ?? NSNull()
}
