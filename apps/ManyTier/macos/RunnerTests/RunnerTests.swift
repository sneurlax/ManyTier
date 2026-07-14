import Cocoa
import Darwin
import FlutterMacOS
import NetworkExtension
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

    let result = waitForCreate(adapter, request: request)
    guard case .failure(let error as VirtualNetworkAdapterError) = result else {
      return XCTFail("Expected VirtualNetworkAdapterError, got \(result)")
    }
    XCTAssertEqual(error.code, "unsupported")
    XCTAssertEqual(error.message, macOSVirtualNetworkUnsupportedMessage)
    let details = error.details as? [String: Any]
    XCTAssertEqual(details?["networkIdHex"] as? String, "8056c2e21c000001")
    XCTAssertEqual(details?["interfaceName"] as? String, "zt00000100da4a")
    XCTAssertEqual(details?["mtu"] as? Int, 1280)
    XCTAssertEqual(details?["managedAddressCount"] as? Int, 1)
  }

  func testUnsupportedAdapterWriteIncludesPacketDetails() {
    let adapter = UnsupportedVirtualNetworkAdapter()
    let packet = VirtualNetworkPacket(arguments: [
      "interfaceId": "native-1",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x45, 0, 0, 20])),
    ])

    let result = waitForWrite(adapter, packet: packet)
    guard case .failure(let error as VirtualNetworkAdapterError) = result else {
      return XCTFail("Expected VirtualNetworkAdapterError, got \(result)")
    }
    XCTAssertEqual(error.code, "not_available")
    XCTAssertEqual(error.message, "No macOS virtual network interface is active.")
    let details = error.details as? [String: Any]
    XCTAssertEqual(details?["interfaceId"] as? String, "native-1")
    XCTAssertEqual(details?["networkIdHex"] as? String, "8056c2e21c000001")
    XCTAssertEqual(details?["packetLength"] as? Int, 4)
  }

  func testPacketTunnelAdapterReportsSupportOnlyWhenConfigured() {
    let missing = PacketTunnelVirtualNetworkAdapter(
      configuration: PacketTunnelConfiguration(providerBundleIdentifier: nil),
      store: FakePacketTunnelManagerStore()
    )
    XCTAssertEqual(missing.supportDetails["supported"] as? Bool, false)
    XCTAssertEqual(
      missing.supportDetails["reason"] as? String,
      "ManyTierPacketTunnelProviderBundleIdentifier is not configured."
    )

    let configured = PacketTunnelVirtualNetworkAdapter(
      configuration: PacketTunnelConfiguration(
        providerBundleIdentifier: "com.manytier.manytierApp.PacketTunnel"
      ),
      store: FakePacketTunnelManagerStore()
    )
    XCTAssertEqual(configured.supportDetails["supported"] as? Bool, true)
    XCTAssertEqual(
      configured.supportDetails["providerBundleIdentifier"] as? String,
      "com.manytier.manytierApp.PacketTunnel"
    )
  }

  func testPacketTunnelAdapterStartsManagerWithCreateMessage() {
    let store = FakePacketTunnelManagerStore()
    let adapter = PacketTunnelVirtualNetworkAdapter(
      configuration: PacketTunnelConfiguration(
        providerBundleIdentifier: "com.manytier.manytierApp.PacketTunnel"
      ),
      store: store
    )

    let result = waitForCreate(adapter, request: fullRequest())

    guard case .success(let value) = result,
          let response = value as? [String: String] else {
      return XCTFail("Expected create success, got \(result)")
    }
    XCTAssertEqual(response["interfaceId"], "zt00000100da4a")
    XCTAssertEqual(store.providerBundleIdentifiers, [
      "com.manytier.manytierApp.PacketTunnel",
    ])

    let message = store.manager.startedMessage()
    XCTAssertEqual(message["type"] as? String, "create")
    let payload = message["payload"] as? [String: Any]
    XCTAssertEqual(payload?["networkIdHex"] as? String, "8056c2e21c000001")
    XCTAssertEqual(payload?["interfaceName"] as? String, "zt00000100da4a")
    XCTAssertEqual(payload?["nodeAddress"] as? [Int], [0xfa, 0xa9, 0, 0xda, 0x4a])
    XCTAssertEqual(payload?["dictData"] as? [Int], [1, 2, 3])
    XCTAssertEqual(payload?["mtu"] as? Int, 1280)
    XCTAssertEqual((payload?["managedAddresses"] as? [[String: Any]])?.count, 2)
    XCTAssertEqual((payload?["routes"] as? [[String: Any]])?.count, 1)
  }

  func testPacketTunnelAdapterSendsWriteMessages() {
    let store = FakePacketTunnelManagerStore()
    let adapter = PacketTunnelVirtualNetworkAdapter(
      configuration: PacketTunnelConfiguration(
        providerBundleIdentifier: "com.manytier.manytierApp.PacketTunnel"
      ),
      store: store
    )
    _ = waitForCreate(adapter, request: fullRequest())

    let result = waitForWrite(adapter, packet: VirtualNetworkPacket(arguments: [
      "interfaceId": "zt00000100da4a",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x45, 0, 0, 20])),
    ]))

    guard case .success = result else {
      return XCTFail("Expected write success, got \(result)")
    }
    let message = store.manager.providerMessages.lastDictionary()
    XCTAssertEqual(message["type"] as? String, "write")
    let payload = message["payload"] as? [String: Any]
    XCTAssertEqual(payload?["interfaceId"] as? String, "zt00000100da4a")
    XCTAssertEqual(payload?["networkIdHex"] as? String, "8056c2e21c000001")
    XCTAssertEqual(payload?["packet"] as? [Int], [0x45, 0, 0, 20])
  }

  func testPacketTunnelAdapterStopsManagerOnClose() {
    let store = FakePacketTunnelManagerStore()
    let adapter = PacketTunnelVirtualNetworkAdapter(
      configuration: PacketTunnelConfiguration(
        providerBundleIdentifier: "com.manytier.manytierApp.PacketTunnel"
      ),
      store: store
    )
    _ = waitForCreate(adapter, request: fullRequest())

    adapter.closeVirtualNetwork(VirtualNetworkCloseRequest(arguments: [
      "interfaceId": "zt00000100da4a",
      "networkIdHex": "8056c2e21c000001",
    ]))

    XCTAssertEqual(store.manager.stopCalls, 1)
  }

  func testPacketTunnelProviderCommandDecodesCreateMessage() throws {
    let data = try PacketTunnelProviderMessage.create(fullRequest()).data()

    let command = try PacketTunnelProviderMessage.command(from: data)

    guard case .create(let payload) = command else {
      return XCTFail("Expected create command, got \(command)")
    }
    XCTAssertEqual(payload.networkIdHex, "8056c2e21c000001")
    XCTAssertEqual(payload.interfaceName, "zt00000100da4a")
    XCTAssertEqual(payload.nodeAddress, [0xfa, 0xa9, 0, 0xda, 0x4a])
    XCTAssertEqual(payload.dictData, [1, 2, 3])
    XCTAssertEqual(payload.mtu, 1280)
    XCTAssertEqual(payload.managedAddresses.count, 2)
    XCTAssertEqual(payload.managedAddresses[0].family, "ipv4")
    XCTAssertEqual(payload.managedAddresses[0].address, "10.147.20.7")
    XCTAssertEqual(payload.managedAddresses[0].prefixLength, 24)
    XCTAssertEqual(payload.managedAddresses[1].family, "ipv6")
    XCTAssertEqual(payload.managedAddresses[1].address, "fd00::7")
    XCTAssertEqual(payload.routes.count, 1)
    XCTAssertEqual(payload.routes[0].target.address, "10.147.20.0")
    XCTAssertEqual(payload.routes[0].gateway?.address, "10.147.20.1")
  }

  func testPacketTunnelCreatePayloadBuildsNetworkSettings() throws {
    let data = try PacketTunnelProviderMessage.create(fullRequest()).data()
    let command = try PacketTunnelProviderMessage.command(from: data)

    guard case .create(let payload) = command else {
      return XCTFail("Expected create command, got \(command)")
    }
    let settings = try payload.networkSettings()

    XCTAssertEqual(settings.tunnelRemoteAddress, "127.0.0.1")
    XCTAssertEqual(settings.mtu?.intValue, 1280)
    XCTAssertEqual(settings.ipv4Settings?.addresses, ["10.147.20.7"])
    XCTAssertEqual(settings.ipv4Settings?.subnetMasks, ["255.255.255.0"])
    XCTAssertEqual(settings.ipv4Settings?.includedRoutes?.count, 1)
    let ipv4Route = settings.ipv4Settings?.includedRoutes?.first
    XCTAssertEqual(ipv4Route?.destinationAddress, "10.147.20.0")
    XCTAssertEqual(ipv4Route?.destinationSubnetMask, "255.255.255.0")
    XCTAssertEqual(ipv4Route?.gatewayAddress, "10.147.20.1")
    XCTAssertEqual(settings.ipv6Settings?.addresses, ["fd00::7"])
    XCTAssertEqual(settings.ipv6Settings?.networkPrefixLengths, [NSNumber(value: 64)])
    XCTAssertNil(settings.ipv6Settings?.includedRoutes)
  }

  func testPacketTunnelProviderCommandDecodesWriteMessageProtocolFamily() throws {
    let ipv4Data = try PacketTunnelProviderMessage.write(VirtualNetworkPacket(arguments: [
      "interfaceId": "zt00000100da4a",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x45, 0, 0, 20])),
    ])).data()
    let ipv6Data = try PacketTunnelProviderMessage.write(VirtualNetworkPacket(arguments: [
      "interfaceId": "zt00000100da4a",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x60, 0, 0, 0])),
    ])).data()

    guard case .write(let ipv4Payload) = try PacketTunnelProviderMessage.command(from: ipv4Data),
          case .write(let ipv6Payload) = try PacketTunnelProviderMessage.command(from: ipv6Data) else {
      return XCTFail("Expected write commands")
    }

    XCTAssertEqual(ipv4Payload.interfaceId, "zt00000100da4a")
    XCTAssertEqual(ipv4Payload.networkIdHex, "8056c2e21c000001")
    XCTAssertEqual(ipv4Payload.packet, [0x45, 0, 0, 20])
    XCTAssertEqual(ipv4Payload.protocolFamily, NSNumber(value: AF_INET))
    XCTAssertEqual(ipv6Payload.protocolFamily, NSNumber(value: AF_INET6))
  }

  func testPacketTunnelProviderCommandRejectsInvalidPayloads() throws {
    let missingPayload = try JSONSerialization.data(withJSONObject: [
      "type": "create",
    ])
    let unsupportedType = try JSONSerialization.data(withJSONObject: [
      "type": "unknown",
      "payload": [:],
    ])
    let noAddresses = try JSONSerialization.data(withJSONObject: [
      "type": "create",
      "payload": [
        "networkIdHex": "8056c2e21c000001",
        "interfaceName": "zt00000100da4a",
        "nodeAddress": [0xfa, 0xa9, 0, 0xda, 0x4a],
        "dictData": [],
        "managedAddresses": [],
        "routes": [],
      ],
    ])

    XCTAssertThrowsError(try PacketTunnelProviderMessage.command(from: missingPayload)) { error in
      XCTAssertEqual(
        error as? PacketTunnelProviderMessageError,
        .invalidPayload("payload is required")
      )
    }
    XCTAssertThrowsError(try PacketTunnelProviderMessage.command(from: unsupportedType)) { error in
      XCTAssertEqual(error as? PacketTunnelProviderMessageError, .invalidType("unknown"))
    }
    guard case .create(let payload) = try PacketTunnelProviderMessage.command(from: noAddresses) else {
      return XCTFail("Expected create command")
    }
    XCTAssertThrowsError(try payload.networkSettings()) { error in
      XCTAssertEqual(
        error as? PacketTunnelProviderMessageError,
        .invalidPayload("at least one managed IPv4 or IPv6 address is required")
      )
    }
  }

  func testPacketTunnelProviderRuntimeStartAppliesSettingsAndActivatesInterface() throws {
    let runtime = PacketTunnelProviderRuntime()
    let message = try PacketTunnelProviderMessage.create(fullRequest()).data()
    var appliedSettings: NEPacketTunnelNetworkSettings?

    let error = waitForRuntimeStart(
      runtime,
      options: ["manytierMessage": message as NSData],
      applySettings: { settings, completion in
        appliedSettings = settings
        completion(nil)
      }
    )

    XCTAssertNil(error)
    XCTAssertEqual(runtime.activeInterfaceId, "zt00000100da4a")
    XCTAssertEqual(appliedSettings?.mtu?.intValue, 1280)
    XCTAssertEqual(appliedSettings?.ipv4Settings?.addresses, ["10.147.20.7"])
  }

  func testPacketTunnelProviderRuntimeWritesAppPacketsToPacketFlow() throws {
    let runtime = PacketTunnelProviderRuntime()
    try startRuntime(runtime)
    let message = try PacketTunnelProviderMessage.write(VirtualNetworkPacket(arguments: [
      "interfaceId": "zt00000100da4a",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x45, 0, 0, 20])),
    ])).data()
    var writes: [(Data, NSNumber)] = []

    let result = runtime.handleAppMessage(message) { packet, protocolFamily in
      writes.append((packet, protocolFamily))
      return true
    }

    guard case .success = result else {
      return XCTFail("Expected runtime write success, got \(result)")
    }
    XCTAssertEqual(writes.count, 1)
    XCTAssertEqual(writes.first?.0, Data([0x45, 0, 0, 20]))
    XCTAssertEqual(writes.first?.1, NSNumber(value: AF_INET))
  }

  func testPacketTunnelProviderRuntimeRejectsInvalidStateAndPackets() throws {
    let runtime = PacketTunnelProviderRuntime()
    let write = try PacketTunnelProviderMessage.write(VirtualNetworkPacket(arguments: [
      "interfaceId": "zt00000100da4a",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x45, 0, 0, 20])),
    ])).data()

    let missingStartError = waitForRuntimeStart(
      runtime,
      options: nil,
      applySettings: { _, completion in completion(nil) }
    )
    XCTAssertEqual(
      missingStartError as? PacketTunnelProviderRuntimeError,
      .missingStartMessage
    )

    let inactiveResult = runtime.handleAppMessage(write) { _, _ in true }
    guard case .failure(let inactiveError as PacketTunnelProviderRuntimeError) = inactiveResult else {
      return XCTFail("Expected inactive interface failure, got \(inactiveResult)")
    }
    XCTAssertEqual(inactiveError, .inactiveInterface("zt00000100da4a"))

    try startRuntime(runtime)
    let unsupportedProtocol = try PacketTunnelProviderMessage.write(VirtualNetworkPacket(arguments: [
      "interfaceId": "zt00000100da4a",
      "networkIdHex": "8056c2e21c000001",
      "packet": FlutterStandardTypedData(bytes: Data([0x10, 0, 0, 20])),
    ])).data()
    let unsupportedResult = runtime.handleAppMessage(unsupportedProtocol) { _, _ in true }
    guard case .failure(let unsupportedError as PacketTunnelProviderRuntimeError) = unsupportedResult else {
      return XCTFail("Expected unsupported protocol failure, got \(unsupportedResult)")
    }
    XCTAssertEqual(unsupportedError, .unsupportedPacketProtocol)
  }

}

private func fullRequest() -> VirtualNetworkRequest {
  VirtualNetworkRequest(arguments: [
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
}

private func waitForCreate(
  _ adapter: ManyTierVirtualNetworkAdapter,
  request: VirtualNetworkRequest
) -> Result<Any?, Error> {
  let expectation = XCTestExpectation(description: "create virtual network")
  var output: Result<Any?, Error>?
  adapter.createVirtualNetwork(request) { result in
    output = result
    expectation.fulfill()
  }
  XCTWaiter().wait(for: [expectation], timeout: 1)
  return output ?? .failure(TestError.missingCompletion)
}

private func waitForWrite(
  _ adapter: ManyTierVirtualNetworkAdapter,
  packet: VirtualNetworkPacket
) -> Result<Void, Error> {
  let expectation = XCTestExpectation(description: "write virtual packet")
  var output: Result<Void, Error>?
  adapter.writeVirtualPacket(packet) { result in
    output = result
    expectation.fulfill()
  }
  XCTWaiter().wait(for: [expectation], timeout: 1)
  return output ?? .failure(TestError.missingCompletion)
}

private enum TestError: Error {
  case missingCompletion
}

private func startRuntime(_ runtime: PacketTunnelProviderRuntime) throws {
  let message = try PacketTunnelProviderMessage.create(fullRequest()).data()
  let error = waitForRuntimeStart(
    runtime,
    options: ["manytierMessage": message as NSData],
    applySettings: { _, completion in completion(nil) }
  )
  XCTAssertNil(error)
}

private func waitForRuntimeStart(
  _ runtime: PacketTunnelProviderRuntime,
  options: [String: NSObject]?,
  applySettings: @escaping PacketTunnelNetworkSettingsApplier
) -> Error? {
  let expectation = XCTestExpectation(description: "start packet tunnel runtime")
  var output: Error?
  runtime.start(
    options: options,
    applySettings: applySettings
  ) { error in
    output = error
    expectation.fulfill()
  }
  XCTWaiter().wait(for: [expectation], timeout: 1)
  return output
}

private final class FakePacketTunnelManagerStore: PacketTunnelManagerStore {
  let manager = FakePacketTunnelManager()
  var providerBundleIdentifiers: [String] = []

  func loadManager(
    providerBundleIdentifier: String,
    completion: @escaping (Result<PacketTunnelManager, Error>) -> Void
  ) {
    providerBundleIdentifiers.append(providerBundleIdentifier)
    completion(.success(manager))
  }
}

private final class FakePacketTunnelManager: PacketTunnelManager {
  var startOptions: [String: NSObject]?
  var providerMessages: [Data] = []
  var stopCalls = 0

  func start(
    options: [String: NSObject],
    completion: @escaping (Error?) -> Void
  ) {
    startOptions = options
    completion(nil)
  }

  func sendProviderMessage(
    _ data: Data,
    completion: @escaping (Result<Data?, Error>) -> Void
  ) {
    providerMessages.append(data)
    completion(.success(nil))
  }

  func stop() {
    stopCalls += 1
  }

  func startedMessage() -> [String: Any] {
    if let data = startOptions?["manytierMessage"] as? Data {
      return dictionary(from: data)
    }
    if let data = startOptions?["manytierMessage"] as? NSData {
      return dictionary(from: data as Data)
    }
    XCTFail("Expected start options to include manytierMessage")
    return [:]
  }
}

private extension Array where Element == Data {
  func lastDictionary() -> [String: Any] {
    guard let data = last else {
      XCTFail("Expected provider message data")
      return [:]
    }
    return dictionary(from: data)
  }
}

private func dictionary(from data: Data) -> [String: Any] {
  do {
    return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
  } catch {
    XCTFail("Expected JSON dictionary, got \(error)")
    return [:]
  }
}
