import SwiftUI
import UIKit

/// Discovery tab mirroring the Android demo: own-network card plus the live
/// peer list fed by the Rust engine.
struct ContentView: View {
    @StateObject private var model = DiscoveryModel()

    var body: some View {
        NavigationStack {
            List {
                Section("本机网络") {
                    HStack {
                        Text("候选地址").foregroundStyle(.secondary)
                        Spacer()
                        Text("\(model.ownCandidates.count) 个").monospaced().foregroundStyle(.green)
                    }
                    ForEach(model.ownBroadcasts, id: \.self) { b in
                        HStack {
                            Text("子网广播 (防 TUN)").foregroundStyle(.secondary)
                            Spacer()
                            Text(b).monospaced().font(.caption2).foregroundStyle(.green)
                        }
                    }
                }

                Section("附近发现的电脑 / 节点") {
                    if model.peers.isEmpty {
                        VStack(spacing: 6) {
                            Text("📡").font(.largeTitle)
                            Text("正在监听局域网对等心跳...").font(.caption).foregroundStyle(.secondary)
                            Text("或将本 App 展示给桌面端扫码").font(.caption2).foregroundStyle(.tertiary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 24)
                    } else {
                        ForEach(model.peers, id: \.nodeId) { peer in
                            HStack(spacing: 10) {
                                Text(peer.device?.icon ?? "💻").font(.title3)
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 6) {
                                        Text(peer.name).fontWeight(.semibold).lineLimit(1)
                                        Text(peer.device?.model ?? "node")
                                            .font(.caption2)
                                            .padding(.horizontal, 5).padding(.vertical, 1)
                                            .background(Color(.systemGray5), in: Capsule())
                                    }
                                    Text("\(peer.ip):\(peer.udpPort)")
                                        .font(.caption2).monospaced().foregroundStyle(.green)
                                }
                                Spacer()
                                Text("连接").font(.caption).foregroundStyle(.green).fontWeight(.semibold)
                            }
                            .padding(.vertical, 2)
                        }
                    }
                }

                if !model.lastEvent.isEmpty {
                    Section("事件") {
                        Text(model.lastEvent).font(.caption2).monospaced().foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Luciola KMP")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(model.engineOn ? Color.green : Color.red)
                            .frame(width: 7, height: 7)
                        Text(model.engineOn ? "引擎在线" : "引擎离线")
                            .font(.caption).monospaced().foregroundStyle(.secondary)
                    }
                }
            }
        }
        .onAppear {
            let name = UIDevice.current.name.isEmpty ? "iOS Peer" : UIDevice.current.name
            model.start(sessionName: name, port: 17880)
        }
    }
}
