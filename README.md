# KCP-P2P-STUN

**Cross-platform P2P communication library based on KCP protocol**
**基于 KCP 协议的跨平台 P2P 通信库**

Rust core with C ABI exports. Works with C/C++/C#/Python/Java/Swift.

---

## Features / 核心功能

| Feature | Description |
|---------|-------------|
| **KCP Reliable Transport** | UDP-based reliable ordered delivery with 3 modes (Normal / Fast / Turbo) — 基于 UDP 的可靠有序传输 |
| **NAT Traversal** | STUN discovery + burst UDP hole punching + TURN relay fallback — STUN 地址发现 + 爆发式打洞 + TURN 中继兜底 |
| **FEC** | Reed-Solomon erasure coding, auto-adjusts redundancy to packet loss — 前向纠错，根据丢包率自动调整冗余比例 |
| **Encryption** | Per-packet ChaCha20-Poly1305 AEAD (28 bytes overhead) — 包级 AEAD 加密 |
| **DNS Disguise** | Wraps UDP as DNS TXT queries to bypass DPI / firewalls — 伪装为 DNS 查询绕过深度包检测 |
| **Auto Negotiation** | Toggling FEC / encryption / disguise auto-notifies the remote peer — 自动配置协商，零丢包切换 |
| **IPv4/IPv6 Dual Stack** | Independent v4/v6 sockets, compatible with all network environments — 双栈支持 |
| **TURN→P2P Auto Retry** | Periodically re-attempts direct P2P while relayed — 中继状态下自动重试直连 |
| **Auto Reconnect** | Keepalive health monitoring + automatic P2P & signaling reconnection on network disruption — 心跳健康检测 + 网络波动自动重连 |

---

## Architecture / 架构

```
Application (C/C++/C#/Python/Java/Swift/...)
     │
┌────┴────┐
│ p2p-ffi │  C ABI export layer / C ABI 导出层
└────┬────┘
     │
┌────┴─────┐
│ p2p-core │  Core logic / 核心逻辑
│          │
│  ConnectionManager ─── KcpSession
│       │                    │
│  NAT Punch            PacketPipeline
│  (穿透引擎)          FEC → Encrypt → DNS Disguise
│       │
│  DualStackSocket (IPv4/IPv6)
└──────────┘
     │
     ├── p2p-signaling-client (WebSocket signaling / 信令)
     ├── p2p-stun (STUN, RFC 8489)
     └── p2p-turn (TURN relay, RFC 5766)
```

### Packet Pipeline / 数据包处理管线

Each layer can be toggled independently at runtime:

```
Send: App Data → [FEC Encode] → [Encrypt] → [DNS Disguise] → UDP
Recv: UDP → [DNS Unwrap] → [Decrypt] → [FEC Decode] → App Data
```

---

## Connection Flow / 连接流程

```
Alice                    Signaling Server                   Bob
  │ Register("alice")        │                               │
  │─────────────────────────▶│                               │
  │                          │        Register("bob")        │
  │                          │◀──────────────────────────────│
  │                          │                               │
  │ Connect("bob")           │                               │
  │─────────────────────────▶│  IncomingConnection           │
  │                          │──────────────────────────────▶│
  │                          │                         Answer│
  │                          │◀──────────────────────────────│
  │                          │                               │
  │  STUN Binding → Gather candidates (Host/Srflx/Relay)    │
  │  ◀══════ Trickle candidate exchange ══════▶              │
  │  ◀══════ UDP Hole Punching (Burst Probe) ══════▶        │
  │                                                          │
  │  ◀══════════ KCP Data Channel Established ══════════▶   │
```

If hole punching fails → automatic TURN relay fallback.
If relayed, optional auto-retry can seamlessly switch back to P2P.

---

## Quick Start / 快速开始

### 1. Build the library / 编译库

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build (release)
cargo build --release -p p2p-ffi
```

Build artifacts in `target/release/`:

| Platform | Files |
|----------|-------|
| Windows | `p2p.dll` + `p2p.dll.lib` (dynamic) / `p2p.lib` (static) |
| macOS | `libp2p.dylib` / `libp2p.a` |
| Linux | `libp2p.so` / `libp2p.a` |

C header auto-generated at `crates/p2p-ffi/include/p2p.h`.

### 2. Start the signaling server / 启动信令服务器

```bash
cd crates/signaling-server-go
go build -o signaling-server .
./signaling-server -bind 0.0.0.0:8080
```

### 3. Use the C API / 使用 C API

```c
#include "p2p.h"

void on_recv(const char* peer, const uint8_t* data, uint32_t len, void* ctx) {
    printf("Received: %.*s\n", (int)len, data);
}

void on_state(const char* peer, P2pConnectionStateC state, void* ctx) {
    printf("State: %d\n", (int)state);
}

int main() {
    P2pConfigC config = {0};
    config.signaling_url = "ws://your-server:8080";
    config.kcp_mode = 1;  // Fast mode
    config.enable_ipv6 = true;

    P2pHandle* h = p2p_init(&config);
    p2p_set_receive_callback(h, on_recv, NULL);
    p2p_set_state_callback(h, on_state, NULL);
    p2p_register(h, "alice");

    // Connect with 2s punch timeout, fallback to TURN if needed
    p2p_connect(h, "bob", 2000, false);
    p2p_send(h, "bob", (const uint8_t*)"Hello P2P!", 10);

    // Enable encryption (auto key negotiation)
    p2p_enable_encryption(h, "bob");

    // Enable FEC for lossy networks
    p2p_enable_fec(h, "bob", true);

    p2p_shutdown(h);
}
```

---

## C API Reference / API 参考

17 exported functions:

| Function | Description |
|----------|-------------|
| `p2p_init` | Initialize library, returns opaque handle / 初始化 |
| `p2p_shutdown` | Shutdown and free all resources / 关闭并释放资源 |
| `p2p_register` | Register peer ID with signaling server / 注册 |
| `p2p_set_turn_server` | Set/clear TURN server dynamically / 动态配置 TURN |
| `p2p_set_state_callback` | Connection state change callback / 状态回调 |
| `p2p_set_receive_callback` | Data receive callback / 数据接收回调 |
| `p2p_set_incoming_callback` | Incoming connection request callback / 来电回调 |
| `p2p_connect` | Connect to peer (configurable timeout + turn_only) / 连接 |
| `p2p_send` | Send data to connected peer / 发送数据 |
| `p2p_disconnect` | Disconnect from peer / 断开连接 |
| `p2p_get_stats` | Get full connection statistics / 获取统计 |
| `p2p_error_string` | Human-readable error string / 错误描述 |
| `p2p_enable_fec` | Toggle FEC per-peer / 开关 FEC |
| `p2p_enable_encryption` | Enable ChaCha20-Poly1305 encryption / 开启加密 |
| `p2p_disable_encryption` | Disable encryption / 关闭加密 |
| `p2p_enable_dns_disguise` | Toggle DNS protocol disguise / 开关 DNS 伪装 |
| `p2p_enable_p2p_retry` | Toggle auto P2P retry while relayed / 开关 P2P 自动重试 |

Full documentation: [docs/API.md](docs/API.md)

---

## Platform Support / 平台支持

| Platform | Target | Artifact |
|----------|--------|----------|
| Windows x86 | `i686-pc-windows-msvc` | `p2p.dll` / `p2p.lib` |
| Windows x64 | `x86_64-pc-windows-msvc` | `p2p.dll` / `p2p.lib` |
| Windows ARM64 | `aarch64-pc-windows-msvc` | `p2p.dll` / `p2p.lib` |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `libp2p.so` / `libp2p.a` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `libp2p.so` / `libp2p.a` |
| Android ARM64 | `aarch64-linux-android` | `libp2p.so` / `libp2p.a` |
| Android x86 | `i686-linux-android` | `libp2p.so` / `libp2p.a` |
| iOS ARM64 (Device) | `aarch64-apple-ios` | `libp2p.a` |
| iOS ARM64 (Simulator) | `aarch64-apple-ios-sim` | `libp2p.a` |
| macOS ARM64 | `aarch64-apple-darwin` | `libp2p.dylib` / `libp2p.a` |
| macOS x86_64 | `x86_64-apple-darwin` | `libp2p.dylib` / `libp2p.a` |
| macOS Universal | ARM64 + x86_64 (lipo) | `libp2p.dylib` / `libp2p.a` |
| iOS XCFramework | Device + Simulator | `libp2p.xcframework` |

### One-click Build / 一键编译

**Windows / Linux / Android** (run on Windows):

```bat
scripts\build_all.bat
```

Builds 7 targets: Windows x86/x64/ARM64, Linux x86_64/ARM64, Android ARM64/x86.
Requires: Visual Studio 2022, cargo-zigbuild + Zig, Android NDK.

**iOS / macOS** (run on Mac):

```bash
./scripts/build_apple.sh           # All (iOS + macOS + Universal)
./scripts/build_apple.sh ios       # iOS only
./scripts/build_apple.sh macos     # macOS only
```

Builds 4 targets + Universal Binary (lipo) + iOS XCFramework.
Requires: Xcode 14+.

All artifacts output to `release/` directory. See [scripts/BUILD_ENV.md](scripts/BUILD_ENV.md) for full environment setup.

### Manual Cross-compilation / 手动交叉编译

```bash
# Windows x64
cargo build --release -p p2p-ffi --target x86_64-pc-windows-msvc

# Linux x86_64 (requires cargo-zigbuild)
cargo zigbuild --release -p p2p-ffi --target x86_64-unknown-linux-gnu

# Android ARM64 (requires NDK, see .cargo/config.toml for linker)
cargo build --release -p p2p-ffi --target aarch64-linux-android

# iOS ARM64 (Mac only)
cargo build --release -p p2p-ffi --target aarch64-apple-ios

# macOS ARM64 (Mac only)
cargo build --release -p p2p-ffi --target aarch64-apple-darwin
```

---

## KCP Transport Modes / KCP 传输模式

| Mode | Latency | Use Case |
|------|---------|----------|
| Normal (0) | Medium / 中等 | File transfer / 文件传输 |
| Fast (1) | Low / 低 | Gaming, real-time / 游戏、实时通信 |
| Turbo (2) | Ultra-low / 极低 | Competitive gaming, remote desktop / 竞技、远程桌面 |

## FEC Adaptive Strategy / FEC 自适应策略

| Packet Loss | Data : Parity | Bandwidth Overhead |
|-------------|---------------|--------------------|
| < 1% | 10 : 1 | ~10% |
| 1-5% | 8 : 2 | ~25% |
| 5-10% | 6 : 3 | ~50% |
| 10-20% | 4 : 4 | ~100% |
| > 20% | 3 : 5 | ~167% |

---

## Connection States / 连接状态

| State | Value | Description |
|-------|-------|-------------|
| Connecting | 0 | Signaling phase / 信令阶段 |
| Connected | 1 | Direct P2P established / P2P 直连 |
| Relayed | 2 | TURN relay / TURN 中继 |
| Reconnecting | 3 | Attempting recovery / 尝试恢复 |
| Disconnected | 4 | Disconnected / 已断开 |
| Gathering | 5 | Gathering candidates / 收集候选地址 |
| Punching | 6 | Hole punching / UDP 打洞中 |

---

## Project Structure / 项目结构

```
kcp_p2p_stun/
├── crates/
│   ├── p2p-core/               Core library (connection/KCP/punch/pipeline)
│   ├── p2p-ffi/                C ABI exports + auto-generated p2p.h
│   ├── p2p-stun/               STUN client (RFC 8489)
│   ├── p2p-turn/               TURN client (RFC 5766)
│   ├── p2p-signaling-proto/    Signaling message definitions (JSON)
│   ├── p2p-signaling-client/   WebSocket signaling client
│   └── signaling-server-go/    Go signaling server (production)
├── examples/
│   └── p2p_demo.cpp            Interactive demo (chat + file transfer)
├── docs/
│   ├── README.md               Detailed docs (Chinese)
│   ├── API.md                  Full C API reference + multi-language examples
│   └── BUILD.md                Build guide for all platforms
└── scripts/
    ├── build_all.bat           Windows/Linux/Android one-click build (7 targets)
    ├── build_apple.sh          iOS/macOS one-click build (4 targets + Universal)
    └── BUILD_ENV.md            Build environment setup guide
```

---

## Signaling Server / 信令服务器

Go-based WebSocket signaling server included:

```bash
cd crates/signaling-server-go
go build -o signaling-server .
./signaling-server -bind 0.0.0.0:8080 -max-peers 10000
```

Features: peer registration, connection request relay, candidate trickle, ping/pong heartbeat (30s), zombie cleanup (120s), HTTP `/status` endpoint.

---

## Documentation / 文档

- [API Reference / API 参考](docs/API.md) — Full C API docs with C/C++/C#/Python/Java/Swift examples
- [Build Guide / 编译指南](docs/BUILD.md) — Platform-specific build instructions
- [Architecture / 架构详解](docs/README.md) — Detailed architecture and connection flow

---

## Build / 编译

```bash
# Build FFI library (release, current platform)
cargo build --release -p p2p-ffi

# Build entire workspace
cargo build --workspace

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -W clippy::all
```

### All-platform Build / 全平台编译

```bat
:: Windows / Linux / Android (7 targets)
scripts\build_all.bat

:: iOS / macOS (4 targets + Universal Binary + XCFramework)
./scripts/build_apple.sh
```

Release directory structure / 产物目录:

```
release/
├── p2p.h                              C header (cbindgen)
├── Windows/release/
│   ├── x86/        p2p.dll + p2p.lib
│   ├── x64/        p2p.dll + p2p.lib
│   └── aarch64/    p2p.dll + p2p.lib
├── Linux/release/
│   ├── x86_64/     libp2p.so + libp2p.a
│   └── aarch64/    libp2p.so + libp2p.a
├── Android/release/
│   ├── aarch64/    libp2p.so + libp2p.a
│   └── x86/        libp2p.so + libp2p.a
├── iOS/release/
│   ├── aarch64/         libp2p.a  (Device)
│   ├── aarch64-sim/     libp2p.a  (Simulator)
│   └── universal/       libp2p.xcframework  (Device + Simulator)
└── macOS/release/
    ├── aarch64/         libp2p.dylib + libp2p.a  (Apple Silicon)
    ├── x86_64/          libp2p.dylib + libp2p.a  (Intel)
    └── universal/       libp2p.dylib + libp2p.a  (Universal Binary)
```

### Windows Demo

```bat
build_demo.bat
```

### Logging / 日志

```bash
RUST_LOG=info ./my_app                           # Default
RUST_LOG=p2p_core=debug,p2p_stun=debug ./my_app  # Debug
RUST_LOG=trace ./my_app                           # Full trace
```

---

## License

MIT OR Apache-2.0
