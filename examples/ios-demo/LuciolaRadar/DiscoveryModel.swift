import Foundation
import Network
import luciola_uniffiFFI

/// Swift-side glue over the uniffi engine. The heavy supervision (stable
/// identity, in-place restart, bind retry, idle tracking) lives in Rust; this
/// adds the iOS platform pieces: NWPathMonitor-driven rebuilds and a watchdog
/// mirroring the KMP/Android core (debounce + bounded consecutive restarts).
@MainActor
final class DiscoveryModel: ObservableObject {
    @Published var peers: [DiscoveredPeer] = []
    @Published var engineOn = false
    @Published var ownCandidates: [String] = []
    @Published var ownBroadcasts: [String] = []
    @Published var lastEvent: String = ""

    private var session: DiscoverySession?
    private let monitor = NWPathMonitor()
    private var monitorStarted = false
    private var firstPathUpdate = true
    private var restartWorkItem: DispatchWorkItem?
    private var watchdogConsecutive = 0
    private var lastActivity = Date()
    private let watchdogInterval: TimeInterval = 15
    private let watchdogIdle: TimeInterval = 45
    private let watchdogMaxConsecutive = 3

    func start(sessionName: String, port: UInt16 = 17878, manualPeers: [ManualPeer] = []) {
        do {
            let s = try DiscoverySession(name: sessionName, port: port, manualPeers: manualPeers, product: "luciola-radar-demo")
            s.start(listener: PeerRelay(
                onPeer: { [weak self] peer in
                    Task { @MainActor in self?.onPeer(peer) }
                },
                onLost: { [weak self] nodeId in
                    Task { @MainActor in
                        self?.peers.removeAll { $0.nodeId == nodeId }
                        self?.lastEvent = "peer lost: \(nodeId)"
                    }
                },
                onError: { [weak self] code, message in
                    Task { @MainActor in
                        self?.lastEvent = "engine error [\(code)]: \(message)"
                    }
                }
            ))
            session = s
            engineOn = true
            // The engine binds asynchronously (with retry); reflect the real
            // bind outcome shortly after start instead of claiming online.
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
                self?.engineOn = self?.session?.isBound() ?? false
                if self?.engineOn == false {
                    self?.lastEvent = "discovery port occupied — engine not bound"
                }
            }
            ownCandidates = localCandidateAddresses()
            ownBroadcasts = subnetBroadcastAddresses()
            startNetworkWatcher()
            scheduleWatchdog()
        } catch {
            engineOn = false
            lastEvent = "engine start failed: \(error)"
        }
    }

    private func onPeer(_ peer: DiscoveredPeer) {
        lastActivity = Date()
        watchdogConsecutive = 0
        if let idx = peers.firstIndex(where: { $0.nodeId == peer.nodeId }) {
            peers[idx] = peer
        } else {
            peers.append(peer)
            lastEvent = "found \(peer.name) @ \(peer.ip)"
        }
    }

    // MARK: network watcher

    private func startNetworkWatcher() {
        guard !monitorStarted else { return }
        monitorStarted = true
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                guard let self else { return }
                if self.firstPathUpdate { self.firstPathUpdate = false; return }
                guard path.status == .satisfied else { return }
                self.scheduleRestart(reason: "network change")
            }
        }
        monitor.start(queue: DispatchQueue(label: "luciola.netmon"))
    }

    private func scheduleRestart(reason: String) {
        guard restartWorkItem == nil else { return } // debounce bursts
        let item = DispatchWorkItem { [weak self] in
            guard let self, let s = self.session else { return }
            s.restart()
            self.lastEvent = "engine rebuilt: \(reason)"
        }
        restartWorkItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8, execute: item)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            if self?.restartWorkItem === item { self?.restartWorkItem = nil }
        }
    }

    // MARK: watchdog

    private func scheduleWatchdog() {
        DispatchQueue.main.asyncAfter(deadline: .now() + watchdogInterval) { [weak self] in
            guard let self else { return }
            let idle = self.session?.secondsSinceIdle() ?? 0
            let networkUp = self.monitor.currentPath.status == .satisfied
            if networkUp && idle > self.watchdogIdle && self.watchdogConsecutive < self.watchdogMaxConsecutive {
                self.watchdogConsecutive += 1
                self.session?.restart()
                self.lastEvent = "watchdog rebuild #\(self.watchdogConsecutive) (idle \(Int(idle))s)"
            }
            self.scheduleWatchdog()
        }
    }
}

/// Bridges the uniffi callback interface to closures.
final class PeerRelay: OnPeerDiscovered {
    private let onPeer: (DiscoveredPeer) -> Void
    private let onLost: (String) -> Void
    private let onError: (String, String) -> Void
    init(
        onPeer: @escaping (DiscoveredPeer) -> Void,
        onLost: @escaping (String) -> Void = { _ in },
        onError: @escaping (String, String) -> Void = { _, _ in }
    ) {
        self.onPeer = onPeer
        self.onLost = onLost
        self.onError = onError
    }
    func onPeerDiscovered(peer: DiscoveredPeer) { onPeer(peer) }
    func onPeerUpdated(peer: DiscoveredPeer) { onPeer(peer) }
    func onPeerLost(nodeId: String) { onLost(nodeId) }
    func onError(code: String, message: String) { onError(code, message) }
}
