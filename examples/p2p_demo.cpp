/**
 * p2p_demo.cpp - KCP-P2P-STUN Demo (Windows Console)
 *
 * Build (MSVC static lib):
 *   cl /EHsc /std:c++17 /O2 /utf-8 ^
 *     /I "crates\p2p-ffi\include" ^
 *     "examples\p2p_demo.cpp" ^
 *     /Fe:"target\release\p2p_demo.exe" ^
 *     /link /LIBPATH:"target\release" ^
 *     p2p.lib ws2_32.lib userenv.lib ntdll.lib bcrypt.lib advapi32.lib kernel32.lib
 *
 * Usage:
 *   p2p_demo.exe <my_peer_id>
 *
 * Commands (after registration):
 *   connect <peer_id>          - Connect to a remote peer
 *   send <peer_id> <message>   - Send a text message
 *   file <peer_id> <path>      - Send a file
 *   stats <peer_id>            - Show connection statistics
 *   fec <peer_id> on|off       - Toggle FEC
 *   encrypt <peer_id> on|off   - Toggle encryption
 *   dns <peer_id> on|off       - Toggle DNS disguise
 *   help                       - Show commands
 *   quit                       - Exit
 */

#include "p2p.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <fstream>
#include <algorithm>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------
using SteadyClock = std::chrono::steady_clock;
using TimePoint   = SteadyClock::time_point;

static TimePoint g_app_start;

static std::string timestamp() {
    auto now  = SteadyClock::now();
    auto ms   = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_app_start).count();
    long sec  = static_cast<long>(ms / 1000);
    long frac = static_cast<long>(ms % 1000);
    char buf[32];
    snprintf(buf, sizeof(buf), "[%ld.%03lds]", sec, frac);
    return buf;
}

// ---------------------------------------------------------------------------
// Console color helpers (Windows)
// ---------------------------------------------------------------------------
#ifdef _WIN32
enum class Color { Reset, Green, Yellow, Red, Cyan, Magenta, White };

static void set_color(Color c) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    switch (c) {
        case Color::Green:   SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case Color::Yellow:  SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case Color::Red:     SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY); break;
        case Color::Cyan:    SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
        case Color::Magenta: SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
        case Color::White:   SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
        default:             SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
    }
}
#else
enum class Color { Reset, Green, Yellow, Red, Cyan, Magenta, White };
static void set_color(Color) {}
#endif

static void log_info(const char* fmt, ...) {
    set_color(Color::Cyan);
    printf("%s ", timestamp().c_str());
    set_color(Color::Reset);
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static void log_ok(const char* fmt, ...) {
    set_color(Color::Green);
    printf("%s ", timestamp().c_str());
    set_color(Color::Reset);
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static void log_warn(const char* fmt, ...) {
    set_color(Color::Yellow);
    printf("%s ", timestamp().c_str());
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    set_color(Color::Reset);
    printf("\n");
    fflush(stdout);
}

static void log_err(const char* fmt, ...) {
    set_color(Color::Red);
    printf("%s ", timestamp().c_str());
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    set_color(Color::Reset);
    printf("\n");
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// Application protocol (over KCP reliable channel)
//
//   [1 byte type] [payload...]
//
//   0x01  TEXT     : UTF-8 text message
//   0x02  FILE_HDR : uint64_le(file_size) + filename (UTF-8, no null)
//   0x03  FILE_DATA: raw chunk (up to 32 KB)
//   0x04  FILE_END : uint64_le(total_bytes) - transfer complete
// ---------------------------------------------------------------------------
static constexpr uint8_t MSG_HEARTBEAT = 0x00;  // keepalive (silently ignored by receiver)
static constexpr uint8_t MSG_TEXT      = 0x01;
static constexpr uint8_t MSG_FILE_HDR  = 0x02;
static constexpr uint8_t MSG_FILE_DATA = 0x03;
static constexpr uint8_t MSG_FILE_END  = 0x04;

static constexpr uint32_t FILE_CHUNK_SIZE = 32 * 1024; // 32 KB

// ---------------------------------------------------------------------------
// File receive state
// ---------------------------------------------------------------------------
struct FileRecvCtx {
    std::string  filename;
    uint64_t     total_size  = 0;
    uint64_t     received    = 0;
    std::ofstream ofs;
    TimePoint    start_time;
};

static std::mutex                                  g_recv_mutex;
static std::unordered_map<std::string, FileRecvCtx> g_recv_map;   // peer_id -> recv ctx

// ---------------------------------------------------------------------------
// Connection timing tracker
// ---------------------------------------------------------------------------
struct ConnTiming {
    TimePoint start;                    // when connect() was called
    TimePoint gathering_at;
    TimePoint punching_at;
    TimePoint connected_at;
    bool      timed = false;
};

static std::mutex                                     g_timing_mutex;
static std::unordered_map<std::string, ConnTiming>    g_timing_map;

// ---------------------------------------------------------------------------
// Connection state tracker (local mirror of library state)
// ---------------------------------------------------------------------------
static std::mutex                                                g_conn_mutex;
static std::unordered_map<std::string, P2pConnectionStateC>     g_conn_states;

static bool is_connected(const std::string& peer_id) {
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    auto it = g_conn_states.find(peer_id);
    if (it == g_conn_states.end()) return false;
    return it->second == P2pConnectionStateC::Connected
        || it->second == P2pConnectionStateC::Relayed;
}

static const char* get_peer_state_name(const std::string& peer_id) {
    std::lock_guard<std::mutex> lk(g_conn_mutex);
    auto it = g_conn_states.find(peer_id);
    if (it == g_conn_states.end()) return "No connection";
    switch (it->second) {
        case P2pConnectionStateC::Connecting:    return "Connecting";
        case P2pConnectionStateC::Connected:     return "Connected (P2P)";
        case P2pConnectionStateC::Relayed:       return "Relayed (TURN)";
        case P2pConnectionStateC::Reconnecting:  return "Reconnecting";
        case P2pConnectionStateC::Disconnected:  return "Disconnected";
        case P2pConnectionStateC::Gathering:     return "Gathering";
        case P2pConnectionStateC::Punching:      return "Punching";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
static P2pHandle*       g_handle       = nullptr;
static std::string      g_my_peer_id;
static std::atomic<bool> g_running{true};

// ---------------------------------------------------------------------------
// Heartbeat keepalive thread
//
// Sends a 1-byte MSG_HEARTBEAT to every connected peer every 3 seconds.
// This keeps the UDP hole-punch path alive through stateful firewalls/NATs
// that would otherwise expire the UDP mapping after ~15-30s of silence.
// ---------------------------------------------------------------------------
static std::thread g_heartbeat_thread;

static void heartbeat_loop() {
    const uint8_t hb_msg[1] = { MSG_HEARTBEAT };
    while (g_running) {
        // Sleep in small increments so we can exit quickly
        for (int i = 0; i < 30 && g_running; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!g_running) break;

        // Send heartbeat to all connected peers
        std::vector<std::string> connected_peers;
        {
            std::lock_guard<std::mutex> lk(g_conn_mutex);
            for (auto& [pid, st] : g_conn_states) {
                if (st == P2pConnectionStateC::Connected ||
                    st == P2pConnectionStateC::Relayed) {
                    connected_peers.push_back(pid);
                }
            }
        }
        for (auto& pid : connected_peers) {
            p2p_send(g_handle, pid.c_str(), hb_msg, 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const char* state_name(P2pConnectionStateC s) {
    switch (s) {
        case P2pConnectionStateC::Connecting:    return "Connecting";
        case P2pConnectionStateC::Connected:     return "Connected (P2P direct)";
        case P2pConnectionStateC::Relayed:       return "Relayed (TURN)";
        case P2pConnectionStateC::Reconnecting:  return "Reconnecting";
        case P2pConnectionStateC::Disconnected:  return "Disconnected";
        case P2pConnectionStateC::Gathering:     return "Gathering candidates (STUN)";
        case P2pConnectionStateC::Punching:      return "Punching (UDP hole-punch)";
    }
    return "Unknown";
}

static std::string format_bytes(uint64_t bytes) {
    char buf[64];
    if (bytes >= 1024ULL * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.2f GB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024ULL * 1024)
        snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, sizeof(buf), "%.2f KB", bytes / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    return buf;
}

static std::string format_speed(uint64_t bytes_per_sec) {
    return format_bytes(bytes_per_sec) + "/s";
}

static void write_u64_le(uint8_t* dst, uint64_t v) {
    for (int i = 0; i < 8; i++) { dst[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

static uint64_t read_u64_le(const uint8_t* src) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) { v = (v << 8) | src[i]; }
    return v;
}

// Extract just the filename from a full path
static std::string basename_of(const std::string& path) {
    auto pos = path.find_last_of("/\\");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------
static void on_state(const char* peer_id, P2pConnectionStateC state, void*) {
    auto now = SteadyClock::now();
    std::string pid(peer_id);

    // Track connection state locally
    {
        std::lock_guard<std::mutex> lk(g_conn_mutex);
        g_conn_states[pid] = state;
    }

    // Update timing
    {
        std::lock_guard<std::mutex> lk(g_timing_mutex);
        auto& t = g_timing_map[pid];
        switch (state) {
            case P2pConnectionStateC::Gathering:
                t.gathering_at = now;
                break;
            case P2pConnectionStateC::Punching:
                t.punching_at = now;
                break;
            case P2pConnectionStateC::Connected:
            case P2pConnectionStateC::Relayed:
                t.connected_at = now;
                break;
            default: break;
        }
    }

    // Print state
    switch (state) {
        case P2pConnectionStateC::Connected:
        case P2pConnectionStateC::Relayed:
            set_color(Color::Green);
            break;
        case P2pConnectionStateC::Disconnected:
            set_color(Color::Red);
            break;
        default:
            set_color(Color::Yellow);
            break;
    }

    printf("\n%s [%s] State -> %s\n", timestamp().c_str(), peer_id, state_name(state));
    set_color(Color::Reset);

    // Print timing summary on connection established
    if (state == P2pConnectionStateC::Connected || state == P2pConnectionStateC::Relayed) {
        std::lock_guard<std::mutex> lk(g_timing_mutex);
        auto it = g_timing_map.find(pid);
        if (it != g_timing_map.end() && !it->second.timed) {
            auto& t = it->second;
            t.timed = true;

            auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                t.connected_at - t.start).count();
            auto gather_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                t.punching_at - t.gathering_at).count();
            auto punch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                t.connected_at - t.punching_at).count();

            set_color(Color::Magenta);
            printf("  +-----------------------------------------\n");
            printf("  | Connection Timing Summary\n");
            printf("  |   Total:     %lld ms\n", (long long)total_ms);
            if (gather_ms > 0)
                printf("  |   Gathering: %lld ms\n", (long long)gather_ms);
            if (punch_ms > 0)
                printf("  |   Punching:  %lld ms\n", (long long)punch_ms);

            // Determine mode string and remote address
            std::string remote_addr_str;
            bool is_ipv6 = false;
            {
                P2pStatsC stats{};
                if (p2p_get_stats(g_handle, pid.c_str(), &stats) == P2pErrorCode::Ok) {
                    remote_addr_str = (const char*)stats.remote_addr;
                    is_ipv6 = remote_addr_str.find(':') != std::string::npos
                              && remote_addr_str.find('[') != std::string::npos;
                }
            }

            if (state == P2pConnectionStateC::Connected) {
                printf("  |   Mode:      %s P2P Direct\n", is_ipv6 ? "IPv6" : "IPv4");
            } else {
                printf("  |   Mode:      TURN Relay\n");
            }
            if (!remote_addr_str.empty())
                printf("  |   Remote:    %s\n", remote_addr_str.c_str());
            printf("  +-----------------------------------------\n");
            set_color(Color::Reset);
        }
    }

    // Reprint prompt so user knows they can still type
    set_color(Color::Green);
    printf("%s> ", g_my_peer_id.c_str());
    set_color(Color::Reset);
    fflush(stdout);
}

static void on_recv(const char* peer_id, const uint8_t* data, uint32_t data_len, void*) {
    if (data_len < 1) return;
    std::string pid(peer_id);
    uint8_t msg_type = data[0];
    const uint8_t* payload = data + 1;
    uint32_t payload_len   = data_len - 1;

    switch (msg_type) {
    // ---- Heartbeat (keepalive) - silently ignore ----
    case MSG_HEARTBEAT:
        break;

    // ---- Text message ----
    case MSG_TEXT: {
        std::string text(reinterpret_cast<const char*>(payload), payload_len);
        // Print on a fresh line to avoid mixing with the input prompt
        printf("\n");
        set_color(Color::White);
        printf("%s [%s] >> %s\n", timestamp().c_str(), peer_id, text.c_str());
        set_color(Color::Reset);
        // Reprint prompt hint
        set_color(Color::Green);
        printf("%s> ", g_my_peer_id.c_str());
        set_color(Color::Reset);
        fflush(stdout);
        break;
    }

    // ---- File header ----
    case MSG_FILE_HDR: {
        if (payload_len < 8) break;
        uint64_t file_size = read_u64_le(payload);
        std::string filename(reinterpret_cast<const char*>(payload + 8), payload_len - 8);

        // Save to current directory with "recv_" prefix to avoid overwriting
        std::string save_path = "recv_" + filename;

        std::lock_guard<std::mutex> lk(g_recv_mutex);
        auto& ctx = g_recv_map[pid];
        ctx.filename   = save_path;
        ctx.total_size = file_size;
        ctx.received   = 0;
        ctx.start_time = SteadyClock::now();
        ctx.ofs.open(save_path, std::ios::binary | std::ios::trunc);

        if (!ctx.ofs.is_open()) {
            log_err("Failed to create file: %s", save_path.c_str());
            g_recv_map.erase(pid);
            break;
        }
        log_info("Receiving file from [%s]: \"%s\" (%s)",
                 peer_id, filename.c_str(), format_bytes(file_size).c_str());
        break;
    }

    // ---- File data chunk ----
    case MSG_FILE_DATA: {
        std::lock_guard<std::mutex> lk(g_recv_mutex);
        auto it = g_recv_map.find(pid);
        if (it == g_recv_map.end()) break;

        auto& ctx = it->second;
        if (ctx.ofs.is_open()) {
            ctx.ofs.write(reinterpret_cast<const char*>(payload), payload_len);
            ctx.received += payload_len;

            // Progress
            double pct = ctx.total_size > 0
                         ? (100.0 * ctx.received / ctx.total_size) : 0.0;
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                SteadyClock::now() - ctx.start_time).count();
            uint64_t speed = elapsed > 0 ? (ctx.received * 1000 / elapsed) : 0;

            printf("\r  Recv: %s / %s  (%.1f%%)  %s    ",
                   format_bytes(ctx.received).c_str(),
                   format_bytes(ctx.total_size).c_str(),
                   pct, format_speed(speed).c_str());
            fflush(stdout);
        }
        break;
    }

    // ---- File transfer complete ----
    case MSG_FILE_END: {
        std::lock_guard<std::mutex> lk(g_recv_mutex);
        auto it = g_recv_map.find(pid);
        if (it == g_recv_map.end()) break;

        auto& ctx = it->second;
        ctx.ofs.close();

        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            SteadyClock::now() - ctx.start_time).count();
        uint64_t avg_speed = elapsed_ms > 0 ? (ctx.received * 1000 / elapsed_ms) : 0;

        printf("\n");
        log_ok("File received: \"%s\" (%s in %lld ms, avg %s)",
               ctx.filename.c_str(),
               format_bytes(ctx.received).c_str(),
               (long long)elapsed_ms,
               format_speed(avg_speed).c_str());

        g_recv_map.erase(it);
        break;
    }

    default:
        log_warn("Unknown message type 0x%02X from [%s] (%u bytes)",
                 msg_type, peer_id, data_len);
        break;
    }
}

static bool on_incoming(const char* peer_id, void*) {
    log_info("Incoming connection from [%s] -> auto-accepting", peer_id);

    // Start timing for incoming connections too
    std::lock_guard<std::mutex> lk(g_timing_mutex);
    auto& t = g_timing_map[peer_id];
    t.start = SteadyClock::now();

    return true;
}

// ---------------------------------------------------------------------------
// Send file (runs in a separate thread)
// ---------------------------------------------------------------------------
static void send_file_thread(std::string peer_id, std::string filepath) {
    std::ifstream ifs(filepath, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        log_err("Cannot open file: %s", filepath.c_str());
        return;
    }

    uint64_t file_size = static_cast<uint64_t>(ifs.tellg());
    ifs.seekg(0);

    std::string fname = basename_of(filepath);

    // 1) Send FILE_HDR
    {
        std::vector<uint8_t> hdr(1 + 8 + fname.size());
        hdr[0] = MSG_FILE_HDR;
        write_u64_le(&hdr[1], file_size);
        memcpy(&hdr[9], fname.data(), fname.size());

        auto err = p2p_send(g_handle, peer_id.c_str(), hdr.data(), (uint32_t)hdr.size());
        if (err != P2pErrorCode::Ok) {
            log_err("Failed to send file header: %s", p2p_error_string(err));
            return;
        }
    }

    log_info("Sending file \"%s\" (%s) to [%s]",
             fname.c_str(), format_bytes(file_size).c_str(), peer_id.c_str());

    // 2) Send FILE_DATA chunks with backpressure
    std::vector<uint8_t> chunk(1 + FILE_CHUNK_SIZE);
    chunk[0] = MSG_FILE_DATA;

    uint64_t  sent      = 0;
    auto      t_start   = SteadyClock::now();

    while (sent < file_size && g_running) {
        uint32_t to_read = static_cast<uint32_t>(
            std::min<uint64_t>(FILE_CHUNK_SIZE, file_size - sent));
        ifs.read(reinterpret_cast<char*>(&chunk[1]), to_read);
        uint32_t actually_read = static_cast<uint32_t>(ifs.gcount());
        if (actually_read == 0) break;

        auto err = p2p_send(g_handle, peer_id.c_str(), chunk.data(), 1 + actually_read);
        if (err != P2pErrorCode::Ok) {
            log_err("Send failed at offset %llu: %s",
                    (unsigned long long)sent, p2p_error_string(err));
            return;
        }
        sent += actually_read;

        // Backpressure: check every 8 chunks
        if ((sent / FILE_CHUNK_SIZE) % 8 == 0) {
            P2pStatsC stats{};
            if (p2p_get_stats(g_handle, peer_id.c_str(), &stats) == P2pErrorCode::Ok) {
                while (stats.send_queue_len + stats.inflight > 128 && g_running) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    p2p_get_stats(g_handle, peer_id.c_str(), &stats);
                }
            }
        }

        // Progress
        double pct = file_size > 0 ? (100.0 * sent / file_size) : 0.0;
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            SteadyClock::now() - t_start).count();
        uint64_t speed = elapsed > 0 ? (sent * 1000 / elapsed) : 0;

        printf("\r  Send: %s / %s  (%.1f%%)  %s    ",
               format_bytes(sent).c_str(),
               format_bytes(file_size).c_str(),
               pct, format_speed(speed).c_str());
        fflush(stdout);
    }

    // 3) Send FILE_END
    {
        uint8_t end_msg[9];
        end_msg[0] = MSG_FILE_END;
        write_u64_le(&end_msg[1], sent);
        p2p_send(g_handle, peer_id.c_str(), end_msg, (uint32_t)sizeof(end_msg));
    }

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        SteadyClock::now() - t_start).count();
    uint64_t avg_speed = elapsed_ms > 0 ? (sent * 1000 / elapsed_ms) : 0;

    printf("\n");
    log_ok("File sent: \"%s\" (%s in %lld ms, avg %s)",
           fname.c_str(), format_bytes(sent).c_str(),
           (long long)elapsed_ms, format_speed(avg_speed).c_str());
}

// ---------------------------------------------------------------------------
// Print stats
// ---------------------------------------------------------------------------
static void print_stats(const char* peer_id) {
    P2pStatsC stats{};
    auto err = p2p_get_stats(g_handle, peer_id, &stats);
    if (err != P2pErrorCode::Ok) {
        log_err("get_stats(%s): %s", peer_id, p2p_error_string(err));
        return;
    }

    std::string remote(reinterpret_cast<const char*>(stats.remote_addr));
    set_color(Color::Cyan);
    printf("+---- Stats: [%s] ---------------------------\n", peer_id);
    printf("| Remote:     %s\n", remote.c_str());
    printf("| Local port: %u\n", stats.local_port);
    printf("| RTT:        %.1f ms  (min %.1f ms, jitter %u us)\n",
           stats.rtt_ms, stats.rtt_min_ms, stats.rtt_var_us);
    printf("| Loss:       %.1f%%\n", stats.loss_percent);
    printf("| Speed:      send %s  recv %s\n",
           format_speed(stats.speed_send).c_str(),
           format_speed(stats.speed_recv).c_str());
    printf("| Bytes:      sent %s  recv %s\n",
           format_bytes(stats.bytes_written).c_str(),
           format_bytes(stats.bytes_read).c_str());
    printf("| Packets:    sent %llu  recv %llu  retx %llu\n",
           (unsigned long long)stats.packets_sent,
           (unsigned long long)stats.packets_recv,
           (unsigned long long)stats.packets_retransmit);
    printf("| Window:     send %u  recv %u  inflight %u  queue %u\n",
           stats.send_window, stats.recv_window, stats.inflight, stats.send_queue_len);
    printf("| Relayed:    %s\n", stats.is_relayed ? "yes (TURN)" : "no (direct P2P)");
    printf("| FEC:        %s  (recoveries: %llu)\n",
           stats.fec_enabled ? "ON" : "OFF",
           (unsigned long long)stats.fec_recoveries);
    printf("| Encryption: %s\n", stats.encryption_enabled ? "ON" : "OFF");
    printf("| DNS Disguise: %s\n", stats.dns_disguise_enabled ? "ON" : "OFF");
    printf("+--------------------------------------------\n");
    set_color(Color::Reset);
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// Print help
// ---------------------------------------------------------------------------
static void print_help() {
    set_color(Color::Cyan);
    printf("\nCommands:\n");
    printf("  connect <peer_id>          Connect to a remote peer\n");
    printf("  send <peer_id> <message>   Send a text message\n");
    printf("  file <peer_id> <path>      Send a file\n");
    printf("  stats <peer_id>            Show connection statistics\n");
    printf("  list                       Show all connections and states\n");
    printf("  fec <peer_id> on|off       Toggle FEC\n");
    printf("  encrypt <peer_id> on|off   Toggle encryption\n");
    printf("  dns <peer_id> on|off       Toggle DNS disguise\n");
    printf("  disconnect <peer_id>       Disconnect from peer\n");
    printf("  help                       Show this help\n");
    printf("  quit                       Exit\n\n");
    set_color(Color::Reset);
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Enable UTF-8 console output
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Enable ANSI / VT100 (for some terminals, optional)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif

    g_app_start = SteadyClock::now();

    if (argc < 2) {
        printf("Usage: %s <my_peer_id>\n", argv[0]);
        return 1;
    }
    g_my_peer_id = argv[1];

    printf("==========================================================\n");
    printf("  KCP-P2P-STUN Demo  (Peer ID: %s)\n", g_my_peer_id.c_str());
    printf("==========================================================\n\n");

    // ---- Initialize ----
    P2pConfigC config{};
    config.signaling_url = "ws://www.54nb.com:8899";
    config.stun_server   = nullptr;  // use defaults
    config.turn_server   = nullptr;
    config.turn_username = nullptr;
    config.turn_password = nullptr;
    config.enable_ipv6   = true;
    config.kcp_mode      = 1;        // Fast mode

    log_info("Initializing P2P library (KCP mode: Fast)...");
    g_handle = p2p_init(&config);
    if (!g_handle) {
        log_err("p2p_init() failed!");
        return 1;
    }
    log_ok("P2P library initialized.");

    // ---- Set callbacks ----
    p2p_set_state_callback(g_handle, on_state, nullptr);
    p2p_set_receive_callback(g_handle, on_recv, nullptr);
    p2p_set_incoming_callback(g_handle, on_incoming, nullptr);
    log_info("Callbacks registered.");

    // ---- Register ----
    log_info("Registering as \"%s\" ...", g_my_peer_id.c_str());
    auto err = p2p_register(g_handle, g_my_peer_id.c_str());
    if (err != P2pErrorCode::Ok) {
        log_err("p2p_register failed: %s", p2p_error_string(err));
        p2p_shutdown(g_handle);
        return 1;
    }
    log_ok("Registered successfully. Waiting for commands.\n");
    print_help();

    // Start heartbeat keepalive thread (sends 1-byte pings every 3s)
    g_heartbeat_thread = std::thread(heartbeat_loop);
    log_info("Heartbeat keepalive started (3s interval).");

    // ---- Command loop ----
    char line[4096];
    while (g_running) {
        set_color(Color::Green);
        printf("%s> ", g_my_peer_id.c_str());
        set_color(Color::Reset);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;

        // Trim trailing newline
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        // Parse command
        std::string input(line);
        std::string cmd, arg1, arg2;

        // Split into tokens
        size_t p1 = input.find(' ');
        if (p1 == std::string::npos) {
            cmd = input;
        } else {
            cmd = input.substr(0, p1);
            size_t p2_start = input.find_first_not_of(' ', p1);
            if (p2_start != std::string::npos) {
                size_t p2 = input.find(' ', p2_start);
                if (p2 == std::string::npos) {
                    arg1 = input.substr(p2_start);
                } else {
                    arg1 = input.substr(p2_start, p2 - p2_start);
                    size_t p3_start = input.find_first_not_of(' ', p2);
                    if (p3_start != std::string::npos)
                        arg2 = input.substr(p3_start);
                }
            }
        }

        // ---- quit ----
        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            g_running = false;
            break;
        }
        // ---- help ----
        else if (cmd == "help" || cmd == "h" || cmd == "?") {
            print_help();
        }
        // ---- connect ----
        else if (cmd == "connect" || cmd == "c") {
            if (arg1.empty()) {
                log_warn("Usage: connect <peer_id>");
                continue;
            }
            log_info("Connecting to [%s] ...", arg1.c_str());
            {
                std::lock_guard<std::mutex> lk(g_timing_mutex);
                auto& t = g_timing_map[arg1];
                t.start = SteadyClock::now();
                t.timed = false;
            }
            err = p2p_connect(g_handle, arg1.c_str());
            if (err != P2pErrorCode::Ok) {
                log_err("p2p_connect failed: %s", p2p_error_string(err));
            }
        }
        // ---- send text ----
        else if (cmd == "send" || cmd == "s") {
            if (arg1.empty() || arg2.empty()) {
                log_warn("Usage: send <peer_id> <message>");
                continue;
            }
            if (!is_connected(arg1)) {
                log_err("Cannot send: [%s] is not connected (state: %s). Wait for 'Connected' state first.",
                        arg1.c_str(), get_peer_state_name(arg1));
                continue;
            }
            std::vector<uint8_t> msg(1 + arg2.size());
            msg[0] = MSG_TEXT;
            memcpy(&msg[1], arg2.data(), arg2.size());
            err = p2p_send(g_handle, arg1.c_str(), msg.data(), (uint32_t)msg.size());
            if (err != P2pErrorCode::Ok) {
                log_err("p2p_send failed: %s", p2p_error_string(err));
            } else {
                set_color(Color::White);
                printf("%s [me] >> %s\n", timestamp().c_str(), arg2.c_str());
                set_color(Color::Reset);
                fflush(stdout);
            }
        }
        // ---- file ----
        else if (cmd == "file" || cmd == "f") {
            if (arg1.empty() || arg2.empty()) {
                log_warn("Usage: file <peer_id> <file_path>");
                continue;
            }
            if (!is_connected(arg1)) {
                log_err("Cannot send file: [%s] is not connected (state: %s). Wait for 'Connected' state first.",
                        arg1.c_str(), get_peer_state_name(arg1));
                continue;
            }
            // Launch file sending in a background thread
            std::thread(send_file_thread, arg1, arg2).detach();
        }
        // ---- list ----
        else if (cmd == "list" || cmd == "ls" || cmd == "l") {
            std::lock_guard<std::mutex> lk(g_conn_mutex);
            if (g_conn_states.empty()) {
                log_info("No connections.");
            } else {
                set_color(Color::Cyan);
                printf("+---- Connections ---------------------------\n");
                for (auto& [pid, st] : g_conn_states) {
                    const char* mark = (st == P2pConnectionStateC::Connected ||
                                        st == P2pConnectionStateC::Relayed) ? "[OK]" : "[..]";
                    printf("|  %s %-20s  %s\n", mark, pid.c_str(), state_name(st));
                }
                printf("+--------------------------------------------\n");
                set_color(Color::Reset);
                fflush(stdout);
            }
        }
        // ---- stats ----
        else if (cmd == "stats" || cmd == "st") {
            if (arg1.empty()) {
                log_warn("Usage: stats <peer_id>");
                continue;
            }
            print_stats(arg1.c_str());
        }
        // ---- fec ----
        else if (cmd == "fec") {
            if (arg1.empty() || arg2.empty()) {
                log_warn("Usage: fec <peer_id> on|off");
                continue;
            }
            bool enable = (arg2 == "on" || arg2 == "1" || arg2 == "true");
            err = p2p_enable_fec(g_handle, arg1.c_str(), enable);
            if (err != P2pErrorCode::Ok)
                log_err("p2p_enable_fec failed: %s", p2p_error_string(err));
            else
                log_ok("FEC %s for [%s]", enable ? "enabled" : "disabled", arg1.c_str());
        }
        // ---- encrypt ----
        else if (cmd == "encrypt" || cmd == "enc") {
            if (arg1.empty() || arg2.empty()) {
                log_warn("Usage: encrypt <peer_id> on|off");
                continue;
            }
            bool enable = (arg2 == "on" || arg2 == "1" || arg2 == "true");
            if (enable) {
                err = p2p_enable_encryption(g_handle, arg1.c_str());
            } else {
                err = p2p_disable_encryption(g_handle, arg1.c_str());
            }
            if (err != P2pErrorCode::Ok)
                log_err("p2p_%s_encryption failed: %s",
                        enable ? "enable" : "disable", p2p_error_string(err));
            else
                log_ok("Encryption %s for [%s]", enable ? "enabled" : "disabled", arg1.c_str());
        }
        // ---- dns disguise ----
        else if (cmd == "dns") {
            if (arg1.empty() || arg2.empty()) {
                log_warn("Usage: dns <peer_id> on|off");
                continue;
            }
            bool enable = (arg2 == "on" || arg2 == "1" || arg2 == "true");
            err = p2p_enable_dns_disguise(g_handle, arg1.c_str(), enable);
            if (err != P2pErrorCode::Ok)
                log_err("p2p_enable_dns_disguise failed: %s", p2p_error_string(err));
            else
                log_ok("DNS disguise %s for [%s]", enable ? "enabled" : "disabled", arg1.c_str());
        }
        // ---- disconnect ----
        else if (cmd == "disconnect" || cmd == "dc") {
            if (arg1.empty()) {
                log_warn("Usage: disconnect <peer_id>");
                continue;
            }
            err = p2p_disconnect(g_handle, arg1.c_str());
            if (err != P2pErrorCode::Ok)
                log_err("p2p_disconnect failed: %s", p2p_error_string(err));
            else
                log_ok("Disconnected from [%s]", arg1.c_str());
        }
        else {
            log_warn("Unknown command: \"%s\". Type 'help' for usage.", cmd.c_str());
        }
    }

    // ---- Shutdown ----
    log_info("Shutting down...");
    g_running = false;
    if (g_heartbeat_thread.joinable())
        g_heartbeat_thread.join();
    p2p_shutdown(g_handle);
    log_ok("Bye.");

    return 0;
}
