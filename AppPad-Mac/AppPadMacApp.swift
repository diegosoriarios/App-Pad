import SwiftUI
import AirPadCore

@main
struct AppPadMacApp: App {
    @StateObject private var cursorInjector = CursorInjector()
    @StateObject private var bleManager: BLECentralManager

    init() {
        let injector = CursorInjector()
        let identity = MacIdentity()
        let store = TrustedDeviceStore()
        _cursorInjector = StateObject(wrappedValue: injector)
        _bleManager = StateObject(wrappedValue: BLECentralManager(
            cursorInjector: injector,
            identity: identity,
            deviceStore: store
        ))
    }

    var body: some Scene {
        MenuBarExtra("AirPad", systemImage: "hand.tap") {
            ContentView(bleManager: bleManager, cursorInjector: cursorInjector)
        }
        .menuBarExtraStyle(.window)
    }
}
