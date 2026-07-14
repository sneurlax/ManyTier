import Cocoa
import FlutterMacOS

private let macOSVirtualNetworkUnsupportedMessage =
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

private final class ManyTierVirtualNetworkChannel {
  private let channel: FlutterMethodChannel

  init(messenger: FlutterBinaryMessenger) {
    channel = FlutterMethodChannel(
      name: "com.manytier.native/virtual_networks",
      binaryMessenger: messenger
    )
    channel.setMethodCallHandler(handle)
  }

  private func handle(call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "virtualNetworkSupport":
      result([
        "supported": false,
        "platform": "macos",
        "reason": macOSVirtualNetworkUnsupportedMessage,
        "requiredHandler": "NetworkExtension packet tunnel provider",
      ])
    case "createVirtualNetwork":
      let request = VirtualNetworkRequest(arguments: call.arguments)
      result(FlutterError(
        code: "unsupported",
        message: macOSVirtualNetworkUnsupportedMessage,
        details: request.details
      ))
    case "writeVirtualPacket":
      result(FlutterError(
        code: "not_available",
        message: "No macOS virtual network interface is active.",
        details: nil
      ))
    case "closeVirtualNetwork":
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }
}

private struct VirtualNetworkRequest {
  let networkIdHex: String?
  let interfaceName: String?
  let mtu: Int?

  init(arguments: Any?) {
    guard let args = arguments as? [String: Any] else {
      networkIdHex = nil
      interfaceName = nil
      mtu = nil
      return
    }
    networkIdHex = args["networkIdHex"] as? String
    interfaceName = args["interfaceName"] as? String
    mtu = args["mtu"] as? Int
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
    return details
  }
}
