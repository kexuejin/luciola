import SwiftUI

@main
struct LuciolaRadarApp: App {
    // Registers the BGTaskScheduler handler before launch completes and receives
    // APNs callbacks — neither is reachable from a SwiftUI `App` alone.
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup { ContentView() }
    }
}
