import SwiftUI

@main
struct BlackHoleAuditApp: App {
    @StateObject private var tunnelController = TunnelController()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(tunnelController)
                .task {
                    await tunnelController.loadOrCreateConfiguration()
                }
        }
    }
}
