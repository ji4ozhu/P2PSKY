# KCP-P2P-STUN

基于 KCP 协议的跨平台 P2P 通信库。Rust 编写，C ABI 导出，支持 C/C++/C#/Python/Java/Swift 调用。

## 核心功能

- **KCP 可靠传输** — 基于 UDP 的可靠有序传输，三种模式 (Normal/Fast/Turbo)
- **NAT 穿透** — STUN 地址发现 + 爆发式 UDP 打洞 + TURN 中继兜底
- **FEC 前向纠错** — Reed-Solomon 纠删码，根据丢包率自动调整冗余比例
- **ChaCha20-Poly1305 加密** — 包级 AEAD 加密，每包 28 字节开销
- **DNS 协议伪装** — 将 UDP 包伪装为 DNS TXT 查询，绕过 DPI/防火墙
- **自动配置协商** — 开启 FEC/加密/DNS 伪装时自动通知对端配合切换
- **IPv4/IPv6 双栈** — 独立的 v4/v6 socket，兼容所有网络环境

## 架构

```
应用程序 (C/C++/C#/Python/...)
     │
┌────┴────┐
│ p2p-ffi │  C ABI 导出层
└────┬────┘
     │
┌────┴─────┐
│ p2p-core │  核心逻辑
│          │
│  ConnectionManager ─── KcpSession
│       │                    │
│  NAT Punch            PacketPipeline
│  (穿透引擎)          FEC → 加密 → DNS 伪装
│       │
│  DualStackSocket (IPv4/IPv6)
└──────────┘
     │
     ├── p2p-signaling-client (WebSocket 信令)
     ├── p2p-stun (STUN NAT 发现, RFC 8489)
     └── p2p-turn (TURN 中继, RFC 5766)
```

## 连接流程

```
Alice                     信令服务器                    Bob
  │ Register("alice")        │                          │
  │─────────────────────────▶│                          │
  │                          │     Register("bob")      │
  │                          │◀─────────────────────────│
  │                          │                          │
  │ Connect("bob")           │                          │
  │─────────────────────────▶│ IncomingConnection       │
  │                          │─────────────────────────▶│
  │                          │                    Answer │
  │                          │◀─────────────────────────│
  │                          │                          │
  │  STUN Binding → 收集候选地址 (Host/Srflx/Relay)     │
  │  ◀═══════ 双向候选地址交换 (Trickle) ═══════▶      │
  │  ◀════════ UDP 打洞 (Burst Probe) ═══════▶         │
  │                                                     │
  │  ◀═══════════ KCP 数据通道建立 ═══════════▶        │
```

## 连接状态

| 状态 | 值 | 说明 |
|------|---|------|
| Connecting | 0 | 信令阶段 |
| Connected | 1 | P2P 直连建立 |
| Relayed | 2 | TURN 中继 |
| Reconnecting | 3 | 连接中断，尝试恢复 |
| Disconnected | 4 | 已断开 |
| Gathering | 5 | 收集候选地址中 |
| Punching | 6 | UDP 打洞中 |

## 数据包处理管线

每个数据包经过可独立开关的处理链：

```
发送: 应用数据 → [FEC 编码] → [加密] → [DNS 伪装] → UDP
接收: UDP → [DNS 解包] → [解密] → [FEC 解码] → 应用数据
```

开启/关闭某一层时，库通过 KCP 内带控制消息自动通知对端，并使用 Transition Mode 短暂接受新旧两种格式，确保切换过程零丢包。

## FEC 自适应策略

| 丢包率 | 数据:冗余 | 带宽开销 |
|-------|----------|---------|
| < 1% | 10:1 | ~10% |
| 1-5% | 8:2 | ~25% |
| 5-10% | 6:3 | ~50% |
| 10-20% | 4:4 | ~100% |
| > 20% | 3:5 | ~167% |

## KCP 传输模式

| 模式 | 值 | 延迟 | 适用场景 |
|------|---|------|---------|
| Normal | 0 | 中等 | 文件传输 |
| Fast | 1 | 低 | 游戏、实时通信 |
| Turbo | 2 | 极低 | 竞技游戏、远程桌面 |

## 快速开始

```c
#include "p2p.h"

void on_recv(const char* peer, const uint8_t* data, uint32_t len, void* ctx) {
    printf("收到: %.*s\n", (int)len, data);
}

void on_state(const char* peer, P2pConnectionStateC state, void* ctx) {
    printf("状态: %d\n", (int)state);
}

int main() {
    P2pConfigC config = {0};
    config.signaling_url = "ws://your-server:8080";
    config.kcp_mode = 1;  // Fast
    config.enable_ipv6 = true;

    P2pHandle* h = p2p_init(&config);
    p2p_set_receive_callback(h, on_recv, NULL);
    p2p_set_state_callback(h, on_state, NULL);
    p2p_register(h, "alice");

    p2p_connect(h, "bob");
    p2p_send(h, "bob", (const uint8_t*)"Hello", 5);

    // 开启加密（自动协商密钥）
    p2p_enable_encryption(h, "bob");

    p2p_shutdown(h);
}
```

## 平台支持

| 平台 | Target | 产物 |
|------|--------|------|
| Windows x86_64 | `x86_64-pc-windows-msvc` | `p2p.dll` / `p2p.lib` |
| macOS ARM64 | `aarch64-apple-darwin` | `libp2p.dylib` / `libp2p.a` |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `libp2p.so` / `libp2p.a` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `libp2p.so` / `libp2p.a` |
| Android ARM64 | `aarch64-linux-android` | `libp2p.so` |
| iOS ARM64 | `aarch64-apple-ios` | `libp2p.a` |

## 信令服务器

项目附带 Go 实现的 WebSocket 信令服务器：

```bash
./signaling-server                          # 默认 0.0.0.0:8080
./signaling-server -bind :9000 -max-peers 5000
```

功能：Peer 注册、连接请求转发、Candidate Trickle、Ping/Pong 心跳、僵尸连接自动清理 (120s)、HTTP 状态接口。

## 项目结构

```
kcp_p2p_stun/
├── crates/
│   ├── p2p-core/               核心库 (连接管理/KCP/打洞/Pipeline)
│   ├── p2p-ffi/                C ABI 导出层 + p2p.h 头文件
│   ├── p2p-stun/               STUN 客户端 (RFC 8489)
│   ├── p2p-turn/               TURN 客户端 (RFC 5766)
│   ├── p2p-signaling-proto/    信令消息定义 (JSON)
│   ├── p2p-signaling-client/   WebSocket 信令客户端
│   └── signaling-server-go/    Go 信令服务器
├── examples/
│   └── p2p_demo.cpp            交互式 Demo (连接/聊天/文件传输)
├── docs/
│   ├── README.md               本文件
│   ├── API.md                  C API 参考手册
│   └── BUILD.md                编译指南
└── scripts/
    ├── build_all.sh            全平台一键编译
    ├── build_android.sh        Android 编译
    └── build_ios.sh            iOS 编译
```

## 文档

- [API 参考](API.md) — 完整 C API 文档 + 多语言调用示例
- [编译指南](BUILD.md) — 各平台编译方法
