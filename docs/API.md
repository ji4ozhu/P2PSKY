# C API 参考

所有平台使用同一个 C 头文件 `include/p2p.h`（由 cbindgen 自动生成）。

---

## 数据类型

### P2pHandle

```c
struct P2pHandle { uint8_t _private[0]; };
```

不透明句柄，由 `p2p_init()` 创建，传给所有后续 API 调用。通过 `p2p_shutdown()` 释放。

### P2pConfigC

```c
struct P2pConfigC {
    const char* signaling_url;    // 信令服务器 WebSocket URL
    const char* stun_server;      // STUN 服务器, NULL = 使用默认
    bool        enable_ipv6;      // 启用 IPv6 双栈
    uint32_t    kcp_mode;         // 0=Normal, 1=Fast, 2=Turbo
};
```

### P2pConnectionStateC

```c
enum P2pConnectionStateC {
    Connecting    = 0,
    Connected     = 1,
    Relayed       = 2,
    Reconnecting  = 3,
    Disconnected  = 4,
    Gathering     = 5,
    Punching      = 6,
};
```

典型状态序列（发起方）：`Connecting → Gathering → Punching → Connected`

### P2pErrorCode

```c
enum P2pErrorCode {
    Ok                       = 0,
    InvalidArgument          = 1,
    NotInitialized           = 2,
    AlreadyInitialized       = 3,
    SignalingConnectionFailed = 4,
    PeerNotFound             = 5,
    ConnectionFailed         = 6,
    Timeout                  = 7,
    SendFailed               = 8,
    BufferTooSmall           = 9,
    AlreadyConnected         = 10,
    NotConnected             = 11,
    EncryptionError          = 12,
    InternalError            = 99,
};
```

### P2pStatsC

```c
struct P2pStatsC {
    // 累计数据
    uint64_t bytes_read;           // 应用层接收总字节
    uint64_t bytes_written;        // 应用层发送总字节
    uint64_t packets_recv;         // UDP 接收总包数
    uint64_t packets_sent;         // UDP 发送总包数
    uint64_t packets_retransmit;   // 重传总包数
    uint64_t fec_packets_sent;     // FEC 冗余包发送总数
    uint64_t fec_recoveries;       // FEC 恢复总次数

    // 实时指标
    float    rtt_ms;               // 平滑 RTT (毫秒)
    float    rtt_min_ms;           // 最低 RTT (毫秒)
    uint32_t rtt_var_us;           // RTT 抖动 (微秒)
    uint32_t rto_ms;               // 重传超时 (毫秒)
    float    loss_percent;         // 丢包率 (0.0 - 100.0)

    // 速度
    uint64_t speed_recv;           // 接收速度 (bytes/sec)
    uint64_t speed_send;           // 发送速度 (bytes/sec)

    // 窗口/缓冲
    uint32_t send_window;          // 发送窗口 (包数)
    uint32_t recv_window;          // 接收窗口 (包数)
    uint32_t inflight;             // 已发未确认包数
    uint32_t send_queue_len;       // 发送缓冲队列长度
    uint32_t recv_queue_len;       // 接收缓冲队列长度

    // 功能标记
    bool     is_relayed;           // 是否 TURN 中继
    bool     fec_enabled;          // FEC 是否启用
    bool     encryption_enabled;   // 加密是否启用
    bool     dns_disguise_enabled; // DNS 伪装是否启用

    // 地址信息
    uint8_t  remote_addr[64];      // 远端地址 (null-terminated, 如 "1.2.3.4:5678")
    uint16_t local_port;           // 本地 UDP 端口
};
```

### 回调函数类型

```c
// 连接状态变化
typedef void (*P2pStateCallbackFn)(const char* peer_id,
                                    P2pConnectionStateC state,
                                    void* user_data);

// 数据接收
typedef void (*P2pReceiveCallbackFn)(const char* peer_id,
                                      const uint8_t* data,
                                      uint32_t data_len,
                                      void* user_data);

// 入站连接请求 (返回 true 接受, false 拒绝)
typedef bool (*P2pIncomingCallbackFn)(const char* peer_id,
                                       void* user_data);
```

---

## API 函数

### 生命周期

#### `p2p_init`
```c
P2pHandle* p2p_init(const P2pConfigC* config);
```
初始化库，创建 tokio 异步运行时。成功返回句柄，失败返回 NULL。

#### `p2p_shutdown`
```c
P2pErrorCode p2p_shutdown(P2pHandle* handle);
```
关闭库，断开所有连接，释放所有资源。调用后句柄不可再用。可安全重复调用。

#### `p2p_register`
```c
P2pErrorCode p2p_register(P2pHandle* handle, const char* peer_id);
```
连接信令服务器并注册 Peer ID。创建连接管理器，绑定 UDP socket，启动接收循环。必须在 `p2p_connect` 之前调用。

#### `p2p_unregister`
```c
P2pErrorCode p2p_unregister(P2pHandle* handle);
```
断开信令服务器，断开所有 peer 连接，销毁连接管理器——但保留 `p2p_init()` 创建的句柄和运行时。调用后可再次调用 `p2p_register()` 重新连接信令服务器。

### 回调设置

#### `p2p_set_state_callback`
```c
P2pErrorCode p2p_set_state_callback(P2pHandle* handle,
                                     P2pStateCallbackFn callback,
                                     void* user_data);
```

#### `p2p_set_receive_callback`
```c
P2pErrorCode p2p_set_receive_callback(P2pHandle* handle,
                                       P2pReceiveCallbackFn callback,
                                       void* user_data);
```

#### `p2p_set_incoming_callback`
```c
P2pErrorCode p2p_set_incoming_callback(P2pHandle* handle,
                                        P2pIncomingCallbackFn callback,
                                        void* user_data);
```

### 连接与数据

#### `p2p_connect`
```c
P2pErrorCode p2p_connect(P2pHandle* handle,
                          const char* remote_peer_id,
                          uint32_t punch_timeout_ms,
                          bool turn_only);
```
异步发起连接。立即返回，进度通过状态回调通知。

**参数**：
- `punch_timeout_ms`：打洞超时（毫秒）。`0` = 使用默认 15 秒。如果在此时间内 P2P 打洞未成功，自动切换 TURN 中继。
- `turn_only`：是否跳过打洞直接走 TURN 中继。`true` = 跳过打洞，TURN 分配完成后直接建立中继连接。`false`（默认）= 正常打洞流程。

流程：信令 → STUN 收集候选 → 候选交换 → UDP 打洞 → KCP 建立。打洞失败自动切换 TURN 中继。`turn_only=true` 时跳过打洞步骤。

#### `p2p_send`
```c
P2pErrorCode p2p_send(P2pHandle* handle,
                       const char* remote_peer_id,
                       const uint8_t* data,
                       uint32_t data_len);
```
发送数据（KCP 可靠传输）。只入队不等待确认。高速发送时应通过 `p2p_get_stats()` 监控 `send_queue_len + inflight` 实现背压控制。

#### `p2p_disconnect`
```c
P2pErrorCode p2p_disconnect(P2pHandle* handle, const char* remote_peer_id);
```

#### `p2p_disconnect_all`
```c
P2pErrorCode p2p_disconnect_all(P2pHandle* handle);
```
断开所有 peer 连接，但保留信令服务器连接和连接管理器。断开后仍可继续调用 `p2p_connect()` 发起新连接。

### 统计

#### `p2p_get_peers`
```c
P2pErrorCode p2p_get_peers(P2pHandle* handle,
                            char* buf,
                            uint32_t buf_len,
                            uint32_t* count_out);
```
获取当前已连接（Connected/Relayed）的 peer 列表。

- `count_out`：接收已连接 peer 数量。
- `buf`：接收 `'\n'` 分隔的 peer ID 列表（null 结尾）。传 NULL 则仅返回数量。
- `buf_len`：缓冲区大小。空间不足时返回 `BufferTooSmall`。

#### `p2p_get_stats`
```c
P2pErrorCode p2p_get_stats(P2pHandle* handle,
                            const char* remote_peer_id,
                            P2pStatsC* stats_out);
```
获取连接的实时统计快照。

### 功能开关

所有功能开关会自动通过 KCP 控制消息与对端协商，无需手动同步。

> **重要：只需在一端调用即可。** FEC、加密、DNS 伪装只需在连接的任意一端启用，对端会通过控制消息自动接收并适配。**请勿两端同时启用**，否则双方同时发起协商会导致冲突错误。

#### `p2p_set_turn_server`
```c
P2pErrorCode p2p_set_turn_server(P2pHandle* handle,
                                  const char* server,
                                  const char* username,
                                  const char* password);
```
动态设置或清除 TURN 服务器配置。可在 `p2p_register()` 之后任意时刻调用。

- **启用 TURN**：传入非 NULL 的 `server`（如 `"turn.example.com:3478"`）、`username`、`password`。
- **禁用 TURN**：`server` 传 NULL（`username` 和 `password` 将被忽略）。

更新后的配置仅影响后续新连接（`p2p_connect()` 时生效）。已有连接的 TURN 状态不受影响。TURN 中继作为 UDP 打洞失败后的兜底方案自动启用。

#### `p2p_enable_fec`
```c
P2pErrorCode p2p_enable_fec(P2pHandle* handle,
                             const char* remote_peer_id,
                             bool enabled);
```
开启/关闭 FEC 前向纠错。冗余比例根据丢包率自动调整。只需在一端调用，对端自动适配。请勿两端同时调用。

#### `p2p_enable_encryption`
```c
P2pErrorCode p2p_enable_encryption(P2pHandle* handle,
                                    const char* remote_peer_id);
```
开启 ChaCha20-Poly1305 加密。密钥自动随机生成并通过控制消息发送给对端。只需在一端调用，对端自动适配。请勿两端同时调用。

#### `p2p_disable_encryption`
```c
P2pErrorCode p2p_disable_encryption(P2pHandle* handle,
                                     const char* remote_peer_id);
```
关闭加密。同样只需在一端调用，对端自动适配。

#### `p2p_enable_dns_disguise`
```c
P2pErrorCode p2p_enable_dns_disguise(P2pHandle* handle,
                                      const char* remote_peer_id,
                                      bool enabled);
```
开启/关闭 DNS 协议伪装。只需在一端调用，对端自动适配。请勿两端同时调用。

#### `p2p_enable_p2p_retry`
```c
P2pErrorCode p2p_enable_p2p_retry(P2pHandle* handle,
                                    const char* remote_peer_id,
                                    bool enabled);
```
动态开关 Relayed 状态下的 P2P 自动重试。开启后，每 5 秒尝试一次打洞（3 秒超时），成功则无缝从 TURN 中继切换到 P2P 直连。

- **per-peer 动态开关**：可在 `p2p_connect()` 之后任意时刻调用，类似 `p2p_enable_fec()`
- 如果调用时连接尚未进入 Relayed 状态，标记会被保存，进入 Relayed 后自动启动重试
- 切换过程中数据传输不中断（先切换地址，再关闭 TURN 包装）
- 成功后状态回调通知 `Connected`

### 工具

#### `p2p_error_string`
```c
const char* p2p_error_string(P2pErrorCode error);
```
返回错误码描述字符串（静态内存，无需释放）。

---

## 各语言调用示例

### C

```c
#include "p2p.h"
#include <stdio.h>
#include <string.h>

void on_state(const char* peer_id, P2pConnectionStateC state, void* ud) {
    printf("Peer %s state: %d\n", peer_id, (int)state);
}

void on_recv(const char* peer_id, const uint8_t* data, uint32_t len, void* ud) {
    printf("Recv %u bytes from %s\n", len, peer_id);
}

bool on_incoming(const char* peer_id, void* ud) {
    return true;  // 接受所有连接
}

int main() {
    P2pConfigC config = {0};
    config.signaling_url = "ws://server:8080";
    config.enable_ipv6   = true;
    config.kcp_mode      = 1;

    P2pHandle* h = p2p_init(&config);
    p2p_set_state_callback(h, on_state, NULL);
    p2p_set_receive_callback(h, on_recv, NULL);
    p2p_set_incoming_callback(h, on_incoming, NULL);

    p2p_register(h, "alice");
    p2p_connect(h, "bob", 0, false);  // 0 = 默认超时, false = 正常打洞

    const char* msg = "Hello";
    p2p_send(h, "bob", (const uint8_t*)msg, strlen(msg));

    // 注意：以下功能开关只需在一端调用，对端自动协商适配，请勿两端同时调用
    p2p_enable_fec(h, "bob", true);
    p2p_enable_encryption(h, "bob");
    p2p_enable_p2p_retry(h, "bob", true);  // Relayed 时自动重试 P2P

    P2pStatsC stats;
    p2p_get_stats(h, "bob", &stats);
    printf("RTT: %.1f ms, Loss: %.1f%%\n", stats.rtt_ms, stats.loss_percent);

    // 断开信令但保留句柄（之后可再次 p2p_register）
    // p2p_unregister(h);

    // 彻底释放所有资源，句柄不可再用
    p2p_shutdown(h);
}
```

链接命令：
```bash
# Windows 静态链接
cl /utf-8 /I include main.c p2p.lib ws2_32.lib bcrypt.lib userenv.lib ntdll.lib advapi32.lib kernel32.lib

# Linux / macOS
gcc -I include -o main main.c -L . -lp2p -lpthread -ldl -lm
```

### C++

```cpp
#include "p2p.h"
#include <iostream>
#include <thread>
#include <atomic>

std::atomic<bool> connected{false};

int main() {
    P2pConfigC config{};
    config.signaling_url = "ws://server:8080";
    config.enable_ipv6   = true;
    config.kcp_mode      = 1;

    auto* h = p2p_init(&config);

    p2p_set_state_callback(h,
        [](const char* peer, P2pConnectionStateC state, void*) {
            if (state == P2pConnectionStateC::Connected) connected = true;
        }, nullptr);

    p2p_set_receive_callback(h,
        [](const char* peer, const uint8_t* data, uint32_t len, void*) {
            std::cout << "From " << peer << ": "
                      << std::string((const char*)data, len) << "\n";
        }, nullptr);

    p2p_set_incoming_callback(h,
        [](const char*, void*) -> bool { return true; }, nullptr);

    p2p_register(h, "my_id");
    p2p_connect(h, "remote_id", 2000, false);  // 2秒打洞超时

    while (!connected)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 发送（带背压控制）
    for (int i = 0; i < 1000; i++) {
        uint8_t buf[1024] = {};
        p2p_send(h, "remote_id", buf, sizeof(buf));

        if ((i + 1) % 10 == 0) {
            P2pStatsC stats{};
            p2p_get_stats(h, "remote_id", &stats);
            while (stats.send_queue_len + stats.inflight > 128) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                p2p_get_stats(h, "remote_id", &stats);
            }
        }
    }

    p2p_shutdown(h);
}
```

### C# (P/Invoke)

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class P2p
{
    const string DLL = "p2p";

    [StructLayout(LayoutKind.Sequential)]
    public struct ConfigC
    {
        public IntPtr signaling_url;
        public IntPtr stun_server;
        [MarshalAs(UnmanagedType.U1)] public bool enable_ipv6;
        public uint kcp_mode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct StatsC
    {
        public ulong bytes_read, bytes_written;
        public ulong packets_recv, packets_sent, packets_retransmit;
        public ulong fec_packets_sent, fec_recoveries;
        public float rtt_ms, rtt_min_ms;
        public uint rtt_var_us, rto_ms;
        public float loss_percent;
        public ulong speed_recv, speed_send;
        public uint send_window, recv_window, inflight;
        public uint send_queue_len, recv_queue_len;
        [MarshalAs(UnmanagedType.U1)] public bool is_relayed;
        [MarshalAs(UnmanagedType.U1)] public bool fec_enabled;
        [MarshalAs(UnmanagedType.U1)] public bool encryption_enabled;
        [MarshalAs(UnmanagedType.U1)] public bool dns_disguise_enabled;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] remote_addr;
        public ushort local_port;

        public string RemoteAddr {
            get {
                int len = Array.IndexOf(remote_addr, (byte)0);
                return Encoding.ASCII.GetString(remote_addr, 0, len < 0 ? 64 : len);
            }
        }
    }

    public delegate void StateCallback(IntPtr peer_id, int state, IntPtr ud);
    public delegate void ReceiveCallback(IntPtr peer_id, IntPtr data, uint len, IntPtr ud);
    [return: MarshalAs(UnmanagedType.U1)]
    public delegate bool IncomingCallback(IntPtr peer_id, IntPtr ud);

    [DllImport(DLL)] public static extern IntPtr p2p_init(ref ConfigC config);
    [DllImport(DLL)] public static extern int p2p_shutdown(IntPtr handle);
    [DllImport(DLL)] public static extern int p2p_register(IntPtr handle, string peer_id);
    [DllImport(DLL)] public static extern int p2p_unregister(IntPtr handle);
    [DllImport(DLL)] public static extern int p2p_connect(IntPtr handle, string peer_id,
                                                            uint punch_timeout_ms,
                                                            [MarshalAs(UnmanagedType.U1)] bool turn_only);
    [DllImport(DLL)] public static extern int p2p_send(IntPtr handle, string peer_id,
                                                        byte[] data, uint len);
    [DllImport(DLL)] public static extern int p2p_disconnect(IntPtr handle, string peer_id);
    [DllImport(DLL)] public static extern int p2p_disconnect_all(IntPtr handle);
    [DllImport(DLL)] public static extern int p2p_get_peers(IntPtr handle,
                                                              StringBuilder buf, uint buf_len,
                                                              out uint count_out);
    [DllImport(DLL)] public static extern int p2p_get_stats(IntPtr handle, string peer_id,
                                                             out StatsC stats);
    [DllImport(DLL)] public static extern int p2p_enable_fec(IntPtr handle, string peer_id,
                                                              [MarshalAs(UnmanagedType.U1)] bool on);
    [DllImport(DLL)] public static extern int p2p_enable_encryption(IntPtr handle, string peer_id);
    [DllImport(DLL)] public static extern int p2p_disable_encryption(IntPtr handle, string peer_id);
    [DllImport(DLL)] public static extern int p2p_enable_dns_disguise(IntPtr handle, string peer_id,
                                                                       [MarshalAs(UnmanagedType.U1)] bool on);
    [DllImport(DLL)] public static extern int p2p_enable_p2p_retry(IntPtr handle, string peer_id,
                                                                     [MarshalAs(UnmanagedType.U1)] bool on);
    [DllImport(DLL)] public static extern int p2p_set_turn_server(IntPtr handle, string server,
                                                                    string username, string password);
    [DllImport(DLL)] public static extern int p2p_set_state_callback(IntPtr h, StateCallback cb, IntPtr ud);
    [DllImport(DLL)] public static extern int p2p_set_receive_callback(IntPtr h, ReceiveCallback cb, IntPtr ud);
    [DllImport(DLL)] public static extern int p2p_set_incoming_callback(IntPtr h, IncomingCallback cb, IntPtr ud);
}

// 示例
class Program {
    static void Main() {
        var url = Marshal.StringToHGlobalAnsi("ws://server:8080");
        var config = new P2p.ConfigC { signaling_url = url, enable_ipv6 = true, kcp_mode = 1 };
        IntPtr h = P2p.p2p_init(ref config);
        Marshal.FreeHGlobal(url);

        P2p.p2p_register(h, "my_id");
        P2p.p2p_connect(h, "peer_id", 0, false);

        byte[] data = Encoding.UTF8.GetBytes("Hello from C#!");
        P2p.p2p_send(h, "peer_id", data, (uint)data.Length);

        P2p.p2p_shutdown(h);
    }
}
```

### Python (ctypes)

```python
import ctypes, os

lib = ctypes.CDLL('./p2p.dll' if os.name == 'nt' else './libp2p.so')

class P2pConfigC(ctypes.Structure):
    _fields_ = [
        ("signaling_url", ctypes.c_char_p),
        ("stun_server", ctypes.c_char_p),
        ("enable_ipv6", ctypes.c_bool),
        ("kcp_mode", ctypes.c_uint32),
    ]

class P2pStatsC(ctypes.Structure):
    _fields_ = [
        ("bytes_read", ctypes.c_uint64), ("bytes_written", ctypes.c_uint64),
        ("packets_recv", ctypes.c_uint64), ("packets_sent", ctypes.c_uint64),
        ("packets_retransmit", ctypes.c_uint64),
        ("fec_packets_sent", ctypes.c_uint64), ("fec_recoveries", ctypes.c_uint64),
        ("rtt_ms", ctypes.c_float), ("rtt_min_ms", ctypes.c_float),
        ("rtt_var_us", ctypes.c_uint32), ("rto_ms", ctypes.c_uint32),
        ("loss_percent", ctypes.c_float),
        ("speed_recv", ctypes.c_uint64), ("speed_send", ctypes.c_uint64),
        ("send_window", ctypes.c_uint32), ("recv_window", ctypes.c_uint32),
        ("inflight", ctypes.c_uint32),
        ("send_queue_len", ctypes.c_uint32), ("recv_queue_len", ctypes.c_uint32),
        ("is_relayed", ctypes.c_bool), ("fec_enabled", ctypes.c_bool),
        ("encryption_enabled", ctypes.c_bool), ("dns_disguise_enabled", ctypes.c_bool),
        ("remote_addr", ctypes.c_uint8 * 64),
        ("local_port", ctypes.c_uint16),
    ]

StateCallbackFn = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p)
ReceiveCallbackFn = ctypes.CFUNCTYPE(None, ctypes.c_char_p,
                                      ctypes.POINTER(ctypes.c_uint8),
                                      ctypes.c_uint32, ctypes.c_void_p)

lib.p2p_init.restype = ctypes.c_void_p
lib.p2p_init.argtypes = [ctypes.POINTER(P2pConfigC)]

def on_state(peer, state, ud):
    print(f"Peer {peer.decode()} state: {state}")

def on_recv(peer, data, length, ud):
    print(f"Recv from {peer.decode()}: {bytes(data[:length])}")

# 保持引用防止 GC 回收
_state_cb = StateCallbackFn(on_state)
_recv_cb = ReceiveCallbackFn(on_recv)

config = P2pConfigC()
config.signaling_url = b"ws://server:8080"
config.enable_ipv6 = True
config.kcp_mode = 1

h = lib.p2p_init(ctypes.byref(config))
lib.p2p_set_state_callback(h, _state_cb, None)
lib.p2p_set_receive_callback(h, _recv_cb, None)
lib.p2p_register(h, b"my_id")
lib.p2p_connect(h, b"peer_id", 0, False)  # 0 = 默认超时, False = 正常打洞
lib.p2p_send(h, b"peer_id", b"Hello from Python!", 18)
# 注意：以下功能开关只需在一端调用，对端自动协商适配，请勿两端同时调用
lib.p2p_enable_p2p_retry(h, b"peer_id", True)  # 开启 P2P 自动重试

# 断开信令但保留句柄（之后可再次 p2p_register）
# lib.p2p_unregister(h)

# 彻底释放所有资源，句柄不可再用
lib.p2p_shutdown(h)
```

### Java (JNA)

```java
import com.sun.jna.*;

public interface P2pLib extends Library {
    P2pLib INSTANCE = Native.load("p2p", P2pLib.class);

    @Structure.FieldOrder({"signaling_url", "stun_server", "enable_ipv6", "kcp_mode"})
    class P2pConfigC extends Structure {
        public String signaling_url, stun_server;
        public boolean enable_ipv6;
        public int kcp_mode;
    }

    @Structure.FieldOrder({"bytes_read", "bytes_written", "packets_recv", "packets_sent",
        "packets_retransmit", "fec_packets_sent", "fec_recoveries",
        "rtt_ms", "rtt_min_ms", "rtt_var_us", "rto_ms", "loss_percent",
        "speed_recv", "speed_send", "send_window", "recv_window", "inflight",
        "send_queue_len", "recv_queue_len",
        "is_relayed", "fec_enabled", "encryption_enabled", "dns_disguise_enabled",
        "remote_addr", "local_port"})
    class P2pStatsC extends Structure {
        public long bytes_read, bytes_written;
        public long packets_recv, packets_sent, packets_retransmit;
        public long fec_packets_sent, fec_recoveries;
        public float rtt_ms, rtt_min_ms;
        public int rtt_var_us, rto_ms;
        public float loss_percent;
        public long speed_recv, speed_send;
        public int send_window, recv_window, inflight, send_queue_len, recv_queue_len;
        public boolean is_relayed, fec_enabled, encryption_enabled, dns_disguise_enabled;
        public byte[] remote_addr = new byte[64];
        public short local_port;
    }

    Pointer p2p_init(P2pConfigC config);
    int p2p_shutdown(Pointer h);
    int p2p_register(Pointer h, String peer_id);
    int p2p_unregister(Pointer h);
    int p2p_connect(Pointer h, String peer_id, int punch_timeout_ms, boolean turn_only);
    int p2p_send(Pointer h, String peer_id, byte[] data, int len);
    int p2p_disconnect(Pointer h, String peer_id);
    int p2p_disconnect_all(Pointer h);
    int p2p_get_peers(Pointer h, byte[] buf, int buf_len, int[] count_out);
    int p2p_get_stats(Pointer h, String peer_id, P2pStatsC stats);
    int p2p_enable_fec(Pointer h, String peer_id, boolean on);
    int p2p_enable_encryption(Pointer h, String peer_id);
    int p2p_disable_encryption(Pointer h, String peer_id);
    int p2p_enable_dns_disguise(Pointer h, String peer_id, boolean on);
    int p2p_enable_p2p_retry(Pointer h, String peer_id, boolean on);
    int p2p_set_turn_server(Pointer h, String server, String username, String password);
}
```

### Swift (iOS)

```swift
// 将 libp2p.a 链接到 Xcode 项目，p2p.h 加入 Bridging Header

var config = P2pConfigC()
config.signaling_url = ("wss://server/ws" as NSString).utf8String
config.enable_ipv6 = true
config.kcp_mode = 1

guard let h = p2p_init(&config) else { fatalError("init failed") }

p2p_register(h, "ios_device")
p2p_connect(h, "peer_id", 0, false)  // 默认超时, 正常打洞

let data: [UInt8] = Array("Hello from iOS!".utf8)
p2p_send(h, "peer_id", data, UInt32(data.count))

// 注意：以下功能开关只需在一端调用，对端自动协商适配，请勿两端同时调用
p2p_enable_encryption(h, "peer_id")
p2p_enable_p2p_retry(h, "peer_id", true)  // Relayed 时自动重试 P2P

// 断开信令但保留句柄（之后可再次 p2p_register）
// p2p_unregister(h)

// 彻底释放所有资源，句柄不可再用
p2p_shutdown(h)
```

---

## 线程安全

- 所有 `p2p_*` 函数线程安全，可从任意线程调用
- 回调在 tokio 后台线程触发，回调内不应长时间阻塞
- 回调内可安全调用 `p2p_send()` 等 API（不会死锁）
- 回调中的 `data` 和 `peer_id` 指针仅在回调期间有效，如需保留请复制

## 内存管理

- `p2p_init()` 返回的句柄必须通过 `p2p_shutdown()` 释放
- `p2p_error_string()` 返回静态字符串，无需释放
- `P2pStatsC.remote_addr` 是值类型字节数组，不涉及指针生命周期

## 背压控制

`p2p_send()` 只入队不等待传输完成。持续高速发送时需监控队列深度：

```
定期检查:
  stats = p2p_get_stats(...)
  while (stats.send_queue_len + stats.inflight > 128):
      sleep(5ms)
      stats = p2p_get_stats(...)
```
