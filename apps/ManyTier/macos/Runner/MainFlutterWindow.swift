import Cocoa
import FlutterMacOS

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
      messenger: flutterViewController.engine.binaryMessenger
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
  }

  private func handle(call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "virtualNetworkSupport":
      result(adapter.supportDetails)
    case "createVirtualNetwork":
      let request = VirtualNetworkRequest(arguments: call.arguments)
      do {
        result(try adapter.createVirtualNetwork(request))
      } catch let error as VirtualNetworkAdapterError {
        result(error.flutterError)
      } catch {
        result(FlutterError(
          code: "native_error",
          message: "\(error)",
          details: nil
        ))
      }
    case "writeVirtualPacket":
      do {
        try adapter.writeVirtualPacket(VirtualNetworkPacket(arguments: call.arguments))
        result(nil)
      } catch let error as VirtualNetworkAdapterError {
        result(error.flutterError)
      } catch {
        result(FlutterError(
          code: "native_error",
          message: "\(error)",
          details: nil
        ))
      }
    case "closeVirtualNetwork":
      adapter.closeVirtualNetwork(VirtualNetworkCloseRequest(arguments: call.arguments))
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }
}

protocol ManyTierVirtualNetworkAdapter {
  var supportDetails: [String: Any] { get }

  func createVirtualNetwork(_ request: VirtualNetworkRequest) throws -> Any?
  func writeVirtualPacket(_ packet: VirtualNetworkPacket) throws
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

final class UnsupportedVirtualNetworkAdapter: ManyTierVirtualNetworkAdapter {
  var supportDetails: [String: Any] {
    [
      "supported": false,
      "platform": "macos",
      "reason": macOSVirtualNetworkUnsupportedMessage,
      "requiredHandler": "NetworkExtension packet tunnel provider",
    ]
  }

  func createVirtualNetwork(_ request: VirtualNetworkRequest) throws -> Any? {
    throw VirtualNetworkAdapterError(
      code: "unsupported",
      message: macOSVirtualNetworkUnsupportedMessage,
      details: request.details
    )
  }

  func writeVirtualPacket(_ packet: VirtualNetworkPacket) throws {
    throw VirtualNetworkAdapterError(
      code: "not_available",
      message: "No macOS virtual network interface is active.",
      details: packet.details
    )
  }

  func closeVirtualNetwork(_ request: VirtualNetworkCloseRequest) {}
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
}

struct VirtualNetworkPacket {
  let interfaceId: String?
  let networkIdHex: String?
  let packet: [UInt8]

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
