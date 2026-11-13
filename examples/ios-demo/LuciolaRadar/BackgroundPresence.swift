import BackgroundTasks
import UIKit

/// iOS background presence.
///
/// ## What iOS will and will not allow
///
/// Unlike Android, iOS has no foreground-service equivalent that can hold a UDP
/// socket answering probes indefinitely. The only sanctioned background modes
/// for this shape of app are:
///
/// * **`fetch`** — `BGAppRefreshTask`, opportunistic, typically well under a
///   minute of runtime, and the system decides when (or whether) to run it.
/// * **`remote-notification`** — a silent APNs push (`content-available: 1`)
///   wakes the app for a short window; this is the only mechanism that can wake
///   a *suspended* app on demand, and it requires a server to send the push.
///
/// `voip` and `audio` would technically keep a socket alive, but both are
/// reserved for their actual purpose and are rejected on review for anything
/// else. Using them here would trade a documented limitation for an App Store
/// rejection.
///
/// So the honest statement is: **iOS presence is foreground-only plus
/// opportunistic refresh.** The engine announces while the app is in the
/// foreground, re-announces on a `BGAppRefreshTask` when the system grants one,
/// and re-announces on a silent push if (and only if) a server sends one. A
/// phone with the app suspended will not answer `alive` probes.
///
/// Everything here is wired but only partly exercisable without an APNs
/// entitlement and a real device: `BGTaskScheduler` does not fire in the
/// simulator on demand, and push delivery needs a signed build.
enum BackgroundPresence {

    /// Must match `BGTaskSchedulerPermittedIdentifiers` in Info.plist.
    static let refreshTaskId = "com.kapp.luciola.demo.LuciolaRadar.refresh"

    /// iOS grants roughly 30 s for a background task. Stop well inside that
    /// rather than being suspended mid-write.
    private static let taskBudget: TimeInterval = 20
    private static let pushBudget: TimeInterval = 15

    /// Must be called before `didFinishLaunchingWithOptions` returns.
    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: refreshTaskId, using: nil) { task in
            guard let refresh = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            handle(refresh)
        }
    }

    /// Queue the next refresh. A task that forgets to reschedule breaks the
    /// chain permanently, so this runs first, before any work.
    static func scheduleNext() {
        let request = BGAppRefreshTaskRequest(identifier: refreshTaskId)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            NSLog("[Luciola] BGTaskScheduler submit failed: \(error)")
        }
    }

    private static func handle(_ task: BGAppRefreshTask) {
        scheduleNext()

        // `finished` is only ever touched on the main queue, so the expiration
        // handler (arbitrary queue) cannot race it.
        var finished = false
        let finish: (Bool) -> Void = { ok in
            DispatchQueue.main.async {
                if finished { return }
                finished = true
                task.setTaskCompleted(success: ok)
            }
        }
        task.expirationHandler = { finish(false) }

        Task { @MainActor in
            DiscoveryModel.shared.backgroundRefresh(budget: taskBudget, completion: finish)
        }
    }

    /// A silent push arrived. Same shape as the refresh task, with a shorter
    /// budget because the system is stricter about push-triggered work.
    static func handleSilentPush(completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        var done = false
        let finish: (Bool) -> Void = { ok in
            DispatchQueue.main.async {
                if done { return }
                done = true
                completionHandler(ok ? .newData : .noData)
            }
        }
        Task { @MainActor in
            DiscoveryModel.shared.backgroundRefresh(budget: pushBudget, completion: finish)
        }
    }
}

/// App delegate for the two things SwiftUI's `App` cannot do on its own:
/// registering the `BGTaskScheduler` handler before launch completes, and
/// receiving APNs callbacks.
final class AppDelegate: NSObject, UIApplicationDelegate {

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        BackgroundPresence.register()
        BackgroundPresence.scheduleNext()
        // Best-effort: without an APNs entitlement this fails immediately and
        // must not take the demo down with it.
        application.registerForRemoteNotifications()
        return true
    }

    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        // A server needs this to address the device. Persisted rather than
        // published: it is a routing identifier, not something the UI shows.
        UserDefaults.standard.set(hex, forKey: "luciola.apns.token")
        Task { @MainActor in
            DiscoveryModel.shared.note("APNs 已注册 (\(hex.prefix(12))…)")
        }
    }

    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        Task { @MainActor in
            DiscoveryModel.shared.note("APNs 不可用: \(error.localizedDescription)")
        }
    }

    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        BackgroundPresence.handleSilentPush(completionHandler: completionHandler)
    }
}
