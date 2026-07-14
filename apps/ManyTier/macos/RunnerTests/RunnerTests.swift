import Cocoa
import FlutterMacOS
import XCTest
@testable import manytier_app

class RunnerTests: XCTestCase {

  func testVirtualNetworkRequestParsesFlutterPayload() {
    let request = VirtualNetworkRequest(arguments: [
      "networkIdHex": "8056c2e21c000001",
      "interfaceName": "zt00000100da4a",
      "nodeAddress": FlutterStandardTypedData(bytes: Data([0xfa, 0xa9, 0x00, 0xda, 0x4a])),
      "dictData": FlutterStandardTypedData(bytes: Data([1, 2, 3])),
      "mtu": NSNumber(value: 1280),
      "managedAddresses": [
        [
          "family": "ipv4",
          "address": "10.147.20.7",
          "prefixLength": NSNumber(value: 24),
          "bytes": FlutterStandardTypedData(bytes: Data([10, 147, 20, 7])),
        ],
        [
          "family": "ipv6",
          "address": "fd00::7",
          "prefixLength": NSNumber(value: 64),
          "bytes": FlutterStandardTypedData(bytes: Data([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7])),
        ],
      ],
      "routes": [
        [
          "target": [
            "family": "ipv4",
            "address": "10.147.20.0",
            "prefixLength": NSNumber(value: 24),
            "bytes": FlutterStandardTypedData(bytes: Data([10, 147, 20, 0])),
          ],
          "gateway": [
            "family": "ipv4",
            "address": "10.147.20.1",
            "prefixLength": NSNumber(value: 0),
            "bytes": FlutterStandardTypedData(bytes: Data([10, 147, 20, 1])),
          ],
          "flags": NSNumber(value: 3),
        ],
      ],
    ])

    XCTAssertEqual(request.networkIdHex, "8056c2e21c000001")
    XCTAssertEqual(request.interfaceName, "zt00000100da4a")
    XCTAssertEqual(request.nodeAddress, [0xfa, 0xa9, 0x00, 0xda, 0x4a])
    XCTAssertEqual(request.dictData, [1, 2, 3])
    XCTAssertEqual(request.mtu, 1280)
    XCTAssertEqual(request.managedAddresses.count, 2)
    XCTAssertEqual(request.managedAddresses[0].family, "ipv4")
    XCTAssertEqual(request.managedAddresses[0].address, "10.147.20.7")
    XCTAssertEqual(request.managedAddresses[0].prefixLength, 24)
    XCTAssertEqual(request.managedAddresses[0].bytes, [10, 147, 20, 7])
    XCTAssertEqual(request.managedAddresses[1].family, "ipv6")
    XCTAssertEqual(request.managedAddresses[1].prefixLength, 64)
    XCTAssertEqual(request.routes.count, 1)
    XCTAssertEqual(request.routes[0].target.address, "10.147.20.0")
    XCTAssertEqual(request.routes[0].gateway?.address, "10.147.20.1")
    XCTAssertEqual(request.routes[0].flags, 3)

    let details = request.details
    XCTAssertEqual(details["networkIdHex"] as? String, "8056c2e21c000001")
    XCTAssertEqual(details["interfaceName"] as? String, "zt00000100da4a")
    XCTAssertEqual(details["mtu"] as? Int, 1280)
    XCTAssertEqual(details["nodeAddressLength"] as? Int, 5)
    XCTAssertEqual(details["dictDataLength"] as? Int, 3)
    XCTAssertEqual(details["managedAddressCount"] as? Int, 2)
    XCTAssertEqual(details["routeCount"] as? Int, 1)
  }

  func testUnsupportedAdapterReportsPacketTunnelRequirement() {
    let adapter = UnsupportedVirtualNetworkAdapter()

    XCTAssertEqual(adapter.supportDetails["supported"] as? Bool, false)
    XCTAssertEqual(adapter.supportDetails["platform"] as? String, "macos")
    XCTAssertEqual(
      adapter.supportDetails["requiredHandler"] as? String,
      "NetworkExtension packet tunnel provider"
    )
    XCTAssertEqual(
      adapter.supportDetails["reason"] as? String,
      macOSVirtualNetworkUnsupportedMessage
    )
  }

  func testUnsupportedAdapterCreateIncludesRequestDetails() {
    let adapter = UnsupportedVirtualNetworkAdapter()
    let request = VirtualNetworkRequest(arguments: [
      "networkIdHex": "8056c2e21c000001",
      "interfaceName": "zt00000100da4a",
      "mtu": NSNumber(value: 1280),
      "managedAddresses": [
        [
          "family": "ipv4",
          "address": "10.147.20.7",
          "prefixLength": NSNumber(value: 24),
          "bytes": FlutterStandardTypedData(bytes: Data([10, 147, 20, 7])),
        ],
      ],
    ])

    XCTAssertThrowsError(try adapter.createVirtualNetwork(request)) { error in
      guard let error = error as? VirtualNetworkAdapterError else {
        return XCTFail("Expected VirtualNetworkAdapterError, got \(error)")
      }
      XCTAssertEqual(error.code, "unsupported")
      XCTAssertEqual(error.message, macOSVirtualNetworkUnsupportedMessage)
      let details = error.details as? [String: Any]
      XCTAssertEqual(details?["networkIdHex"] as? String, "8056c2e21c000001")
      XCTAssertEqual(details?["interfaceName"] as? String, "zt00000100da4a")
      XCTAssertEqual(details?["mtu"] as? Int, 1280)
      XCTAssertEqual(details?["managedAddressCount"] as? Int, 1)
    }
  }

  func testUnsupportedAdapterWriteIncludesPacketDetails() {
    let adapter = UnsupportedVirtualNetworkAdapter()
    let packet = VirtualNetworkPacket(arguments: [
      "interfaceId": "native-1",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x45, 0, 0, 20])),
    ])

    XCTAssertThrowsError(try adapter.writeVirtualPacket(packet)) { error in
      guard let error = error as? VirtualNetworkAdapterError else {
        return XCTFail("Expected VirtualNetworkAdapterError, got \(error)")
      }
      XCTAssertEqual(error.code, "not_available")
      XCTAssertEqual(error.message, "No macOS virtual network interface is active.")
      let details = error.details as? [String: Any]
      XCTAssertEqual(details?["interfaceId"] as? String, "native-1")
      XCTAssertEqual(details?["networkIdHex"] as? String, "8056c2e21c000001")
      XCTAssertEqual(details?["packetLength"] as? Int, 4)
    }
  }

}
