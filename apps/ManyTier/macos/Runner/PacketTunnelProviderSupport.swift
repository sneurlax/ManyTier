import Darwin
import Foundation
import NetworkExtension

enum PacketTunnelProviderMessageError: Error, LocalizedError, Equatable {
  case invalidEnvelope
  case invalidType(String)
  case invalidPayload(String)

  var errorDescription: String? {
    switch self {
    case .invalidEnvelope:
      return "Packet tunnel provider message must be a JSON object."
    case .invalidType(let type):
      return "Unsupported packet tunnel provider message type: \(type)."
    case .invalidPayload(let detail):
      return "Invalid packet tunnel provider payload: \(detail)."
    }
  }
}

struct PacketTunnelProviderMessage {
  let type: String
  let payload: [String: Any]

  static func create(_ request: VirtualNetworkRequest) -> PacketTunnelProviderMessage {
    PacketTunnelProviderMessage(type: "create", payload: request.packetTunnelPayload)
  }

  static func write(_ packet: VirtualNetworkPacket) -> PacketTunnelProviderMessage {
    PacketTunnelProviderMessage(type: "write", payload: packet.packetTunnelPayload)
  }

  func data() throws -> Data {
    try JSONSerialization.data(withJSONObject: [
      "type": type,
      "payload": payload,
    ])
  }

  static func command(from data: Data) throws -> PacketTunnelProviderCommand {
    let object = try JSONSerialization.jsonObject(with: data)
    guard let envelope = object as? [String: Any] else {
      throw PacketTunnelProviderMessageError.invalidEnvelope
    }
    guard let type = envelope["type"] as? String, !type.isEmpty else {
      throw PacketTunnelProviderMessageError.invalidPayload("type is required")
    }
    guard let payload = envelope["payload"] as? [String: Any] else {
      throw PacketTunnelProviderMessageError.invalidPayload("payload is required")
    }
    switch type {
    case "create":
      return .create(try PacketTunnelCreatePayload(payload: payload))
    case "write":
      return .write(try PacketTunnelWritePayload(payload: payload))
    default:
      throw PacketTunnelProviderMessageError.invalidType(type)
    }
  }
}

enum PacketTunnelProviderCommand: Equatable {
  case create(PacketTunnelCreatePayload)
  case write(PacketTunnelWritePayload)
}

enum PacketTunnelProviderRuntimeError: Error, LocalizedError, Equatable {
  case missingStartMessage
  case unexpectedStartCommand
  case unexpectedAppMessage
  case inactiveInterface(String)
  case unsupportedPacketProtocol
  case packetWriteFailed
  case providerUnavailable

  var errorDescription: String? {
    switch self {
    case .missingStartMessage:
      return "Packet tunnel start options did not include manytierMessage."
    case .unexpectedStartCommand:
      return "Packet tunnel start expected a create message."
    case .unexpectedAppMessage:
      return "Packet tunnel app message expected a write message."
    case .inactiveInterface(let interfaceId):
      return "Packet tunnel interface is not active: \(interfaceId)."
    case .unsupportedPacketProtocol:
      return "Packet tunnel write packet is not IPv4 or IPv6."
    case .packetWriteFailed:
      return "Packet tunnel packet flow rejected the packet."
    case .providerUnavailable:
      return "Packet tunnel provider is unavailable."
    }
  }
}

typealias PacketTunnelNetworkSettingsApplier = (
  NEPacketTunnelNetworkSettings,
  @escaping (Error?) -> Void
) -> Void
typealias PacketTunnelPacketWriter = (Data, NSNumber) -> Bool

final class PacketTunnelProviderRuntime {
  private(set) var activeInterfaceId: String?

  func start(
    options: [String: NSObject]?,
    applySettings: @escaping PacketTunnelNetworkSettingsApplier,
    completion: @escaping (Error?) -> Void
  ) {
    guard let messageData = packetTunnelMessageData(options?["manytierMessage"]) else {
      completion(PacketTunnelProviderRuntimeError.missingStartMessage)
      return
    }

    do {
      let command = try PacketTunnelProviderMessage.command(from: messageData)
      guard case .create(let payload) = command else {
        completion(PacketTunnelProviderRuntimeError.unexpectedStartCommand)
        return
      }
      let settings = try payload.networkSettings()
      applySettings(settings) { [weak self] error in
        if let error {
          completion(error)
          return
        }
        self?.activeInterfaceId = payload.interfaceName
        completion(nil)
      }
    } catch {
      completion(error)
    }
  }

  func handleAppMessage(
    _ data: Data,
    writePacket: PacketTunnelPacketWriter
  ) -> Result<Void, Error> {
    do {
      let command = try PacketTunnelProviderMessage.command(from: data)
      guard case .write(let payload) = command else {
        return .failure(PacketTunnelProviderRuntimeError.unexpectedAppMessage)
      }
      guard activeInterfaceId == payload.interfaceId else {
        return .failure(PacketTunnelProviderRuntimeError.inactiveInterface(payload.interfaceId))
      }
      guard let protocolFamily = payload.protocolFamily else {
        return .failure(PacketTunnelProviderRuntimeError.unsupportedPacketProtocol)
      }
      guard writePacket(Data(payload.packet), protocolFamily) else {
        return .failure(PacketTunnelProviderRuntimeError.packetWriteFailed)
      }
      return .success(())
    } catch {
      return .failure(error)
    }
  }

  func stop() {
    activeInterfaceId = nil
  }

  func responseData(for result: Result<Void, Error>) -> Data? {
    switch result {
    case .success:
      return nil
    case .failure(let error):
      return try? JSONSerialization.data(withJSONObject: [
        "error": "\(error)",
      ])
    }
  }
}

class ManyTierPacketTunnelProvider: NEPacketTunnelProvider {
  private let runtime = PacketTunnelProviderRuntime()

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    runtime.start(
      options: options,
      applySettings: { [weak self] settings, completion in
        guard let self else {
          completion(PacketTunnelProviderRuntimeError.providerUnavailable)
          return
        }
        self.setTunnelNetworkSettings(settings, completionHandler: completion)
      },
      completion: completionHandler
    )
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    runtime.stop()
    completionHandler()
  }

  override func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)? = nil
  ) {
    let result = runtime.handleAppMessage(messageData) { [weak self] packet, protocolFamily in
      guard let self else {
        return false
      }
      return self.packetFlow.writePackets([packet], withProtocols: [protocolFamily])
    }
    completionHandler?(runtime.responseData(for: result))
  }
}

struct PacketTunnelCreatePayload: Equatable {
  static let tunnelRemoteAddress = "127.0.0.1"

  let networkIdHex: String
  let interfaceName: String
  let nodeAddress: [UInt8]
  let dictData: [UInt8]
  let mtu: Int?
  let managedAddresses: [PacketTunnelAddressPayload]
  let routes: [PacketTunnelRoutePayload]

  init(payload: [String: Any]) throws {
    networkIdHex = try packetTunnelString(payload["networkIdHex"], name: "networkIdHex")
    interfaceName = try packetTunnelString(payload["interfaceName"], name: "interfaceName")
    nodeAddress = try packetTunnelBytes(payload["nodeAddress"], name: "nodeAddress")
    dictData = try packetTunnelBytes(payload["dictData"], name: "dictData")
    mtu = try packetTunnelOptionalInt(payload["mtu"], name: "mtu")
    managedAddresses = try packetTunnelAddressList(payload["managedAddresses"], name: "managedAddresses")
    routes = try packetTunnelRouteList(payload["routes"], name: "routes")
  }

  func networkSettings() throws -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: PacketTunnelCreatePayload.tunnelRemoteAddress
    )
    if let mtu {
      settings.mtu = NSNumber(value: mtu)
    }

    let ipv4Addresses = managedAddresses.filter { $0.family == "ipv4" }
    if !ipv4Addresses.isEmpty {
      let addresses = try ipv4Addresses.map { try $0.requiredAddress() }
      let subnetMasks = try ipv4Addresses.map { try packetTunnelIPv4SubnetMask(prefixLength: $0.requiredPrefixLength()) }
      let ipv4Settings = NEIPv4Settings(addresses: addresses, subnetMasks: subnetMasks)
      let includedRoutes = try routes.compactMap { try $0.ipv4Route() }
      if !includedRoutes.isEmpty {
        ipv4Settings.includedRoutes = includedRoutes
      }
      settings.ipv4Settings = ipv4Settings
    }

    let ipv6Addresses = managedAddresses.filter { $0.family == "ipv6" }
    if !ipv6Addresses.isEmpty {
      let addresses = try ipv6Addresses.map { try $0.requiredAddress() }
      let prefixes = try ipv6Addresses.map { NSNumber(value: try $0.requiredPrefixLength()) }
      let ipv6Settings = NEIPv6Settings(addresses: addresses, networkPrefixLengths: prefixes)
      let includedRoutes = try routes.compactMap { try $0.ipv6Route() }
      if !includedRoutes.isEmpty {
        ipv6Settings.includedRoutes = includedRoutes
      }
      settings.ipv6Settings = ipv6Settings
    }

    if settings.ipv4Settings == nil && settings.ipv6Settings == nil {
      throw PacketTunnelProviderMessageError.invalidPayload(
        "at least one managed IPv4 or IPv6 address is required"
      )
    }

    return settings
  }
}

struct PacketTunnelAddressPayload: Equatable {
  let family: String
  let address: String?
  let prefixLength: Int?
  let bytes: [UInt8]

  init(payload: [String: Any]) throws {
    family = try packetTunnelString(payload["family"], name: "family")
    address = packetTunnelOptionalString(payload["address"])
    prefixLength = try packetTunnelOptionalInt(payload["prefixLength"], name: "prefixLength")
    bytes = try packetTunnelBytes(payload["bytes"], name: "bytes")
  }

  func requiredAddress() throws -> String {
    guard let address, !address.isEmpty else {
      throw PacketTunnelProviderMessageError.invalidPayload("address is required")
    }
    return address
  }

  func requiredPrefixLength() throws -> Int {
    guard let prefixLength else {
      throw PacketTunnelProviderMessageError.invalidPayload("prefixLength is required")
    }
    return prefixLength
  }
}

struct PacketTunnelRoutePayload: Equatable {
  let target: PacketTunnelAddressPayload
  let gateway: PacketTunnelAddressPayload?
  let flags: Int?

  init(payload: [String: Any]) throws {
    guard let targetPayload = payload["target"] as? [String: Any] else {
      throw PacketTunnelProviderMessageError.invalidPayload("route target is required")
    }
    target = try PacketTunnelAddressPayload(payload: targetPayload)
    if let gatewayPayload = payload["gateway"] as? [String: Any] {
      gateway = try PacketTunnelAddressPayload(payload: gatewayPayload)
    } else {
      gateway = nil
    }
    flags = try packetTunnelOptionalInt(payload["flags"], name: "flags")
  }

  func ipv4Route() throws -> NEIPv4Route? {
    guard target.family == "ipv4" else {
      return nil
    }
    let route = NEIPv4Route(
      destinationAddress: try target.requiredAddress(),
      subnetMask: try packetTunnelIPv4SubnetMask(prefixLength: target.requiredPrefixLength())
    )
    route.gatewayAddress = try gateway?.requiredAddress()
    return route
  }

  func ipv6Route() throws -> NEIPv6Route? {
    guard target.family == "ipv6" else {
      return nil
    }
    let route = NEIPv6Route(
      destinationAddress: try target.requiredAddress(),
      networkPrefixLength: NSNumber(value: try target.requiredPrefixLength())
    )
    route.gatewayAddress = try gateway?.requiredAddress()
    return route
  }
}

struct PacketTunnelWritePayload: Equatable {
  let interfaceId: String
  let networkIdHex: String
  let packet: [UInt8]

  init(payload: [String: Any]) throws {
    interfaceId = try packetTunnelString(payload["interfaceId"], name: "interfaceId")
    networkIdHex = try packetTunnelString(payload["networkIdHex"], name: "networkIdHex")
    packet = try packetTunnelBytes(payload["packet"], name: "packet")
    guard !packet.isEmpty else {
      throw PacketTunnelProviderMessageError.invalidPayload("packet is required")
    }
  }

  var protocolFamily: NSNumber? {
    guard let firstByte = packet.first else {
      return nil
    }
    switch firstByte >> 4 {
    case 4:
      return NSNumber(value: AF_INET)
    case 6:
      return NSNumber(value: AF_INET6)
    default:
      return nil
    }
  }
}

func packetTunnelIPv4SubnetMask(prefixLength: Int) throws -> String {
  guard (0...32).contains(prefixLength) else {
    throw PacketTunnelProviderMessageError.invalidPayload("IPv4 prefixLength must be 0...32")
  }
  let mask: UInt32 = prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - prefixLength)
  return [
    UInt8((mask >> 24) & 0xff),
    UInt8((mask >> 16) & 0xff),
    UInt8((mask >> 8) & 0xff),
    UInt8(mask & 0xff),
  ].map(String.init).joined(separator: ".")
}

private func packetTunnelString(_ value: Any?, name: String) throws -> String {
  guard let string = value as? String, !string.isEmpty else {
    throw PacketTunnelProviderMessageError.invalidPayload("\(name) is required")
  }
  return string
}

private func packetTunnelMessageData(_ value: Any?) -> Data? {
  if let data = value as? Data {
    return data
  }
  if let data = value as? NSData {
    return data as Data
  }
  return nil
}

private func packetTunnelOptionalString(_ value: Any?) -> String? {
  if value is NSNull {
    return nil
  }
  return value as? String
}

private func packetTunnelOptionalInt(_ value: Any?, name: String) throws -> Int? {
  if value == nil || value is NSNull {
    return nil
  }
  if let int = value as? Int {
    return int
  }
  if let number = value as? NSNumber {
    return number.intValue
  }
  throw PacketTunnelProviderMessageError.invalidPayload("\(name) must be an integer")
}

private func packetTunnelBytes(_ value: Any?, name: String) throws -> [UInt8] {
  guard let values = value as? [Any] else {
    throw PacketTunnelProviderMessageError.invalidPayload("\(name) must be a byte array")
  }
  return try values.map { value in
    if let int = value as? Int, (0...255).contains(int) {
      return UInt8(int)
    }
    if let number = value as? NSNumber {
      let int = number.intValue
      if (0...255).contains(int) {
        return UInt8(int)
      }
    }
    throw PacketTunnelProviderMessageError.invalidPayload("\(name) contains a non-byte value")
  }
}

private func packetTunnelAddressList(_ value: Any?, name: String) throws -> [PacketTunnelAddressPayload] {
  guard let values = value as? [Any] else {
    throw PacketTunnelProviderMessageError.invalidPayload("\(name) must be an array")
  }
  return try values.map { value in
    guard let payload = value as? [String: Any] else {
      throw PacketTunnelProviderMessageError.invalidPayload("\(name) entries must be objects")
    }
    return try PacketTunnelAddressPayload(payload: payload)
  }
}

private func packetTunnelRouteList(_ value: Any?, name: String) throws -> [PacketTunnelRoutePayload] {
  guard let values = value as? [Any] else {
    throw PacketTunnelProviderMessageError.invalidPayload("\(name) must be an array")
  }
  return try values.map { value in
    guard let payload = value as? [String: Any] else {
      throw PacketTunnelProviderMessageError.invalidPayload("\(name) entries must be objects")
    }
    return try PacketTunnelRoutePayload(payload: payload)
  }
}
