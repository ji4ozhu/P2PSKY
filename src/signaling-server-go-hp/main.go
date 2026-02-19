//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gobwas/ws"
)

func main() {
	bind := flag.String("bind", "0.0.0.0:8080", "Bind address (host:port)")
	flag.Parse()

	// 创建核心组件
	epoll, err := NewEpoll()
	if err != nil {
		log.Fatalf("Failed to create epoll: %v", err)
	}
	defer epoll.Close()

	registry := NewPeerRegistry()
	sessions := NewSessionTracker()
	reactor := NewReactor(epoll, registry, sessions)
	metrics := NewSystemMetrics()

	// 启动后台清理: 每 30 秒扫描，踢掉 120 秒无活动的连接
	go sweeper(epoll, registry, sessions, 30*time.Second, 120*time.Second)

	// 定时打印服务器状态
	startTime := time.Now()
	go statusPrinter(registry, epoll, startTime)

	fmt.Println("============================================")
	fmt.Println(" KCP-P2P-STUN Signaling Server (Go HP)")
	fmt.Println(" High-Performance Epoll Reactor Model")
	fmt.Println("============================================")
	fmt.Printf("  Bind:      %s\n", *bind)
	fmt.Println("============================================")
	fmt.Println("Listening...")
	fmt.Println()

	// 启动 reactor（在独立 goroutine 中运行事件循环）
	go reactor.Run()

	// 限制并发 WS 握手数量，防止重连风暴时 goroutine 爆炸
	maxHandshakes := runtime.GOMAXPROCS(0) * 512
	if maxHandshakes < 2048 {
		maxHandshakes = 2048
	}
	handshakeSem := make(chan struct{}, maxHandshakes)

	// HTTP 服务器：同一端口处理 WebSocket 升级和 HTTP 状态页面
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// WebSocket 升级请求
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			select {
			case handshakeSem <- struct{}{}:
				defer func() { <-handshakeSem }()
			default:
				http.Error(w, "Server busy", http.StatusServiceUnavailable)
				return
			}
			handleWsUpgrade(w, r, epoll)
			return
		}

		// 下载优化脚本
		if r.URL.Path == "/optimize.sh" {
			w.Header().Set("Content-Type", "text/x-shellscript")
			w.Header().Set("Content-Disposition", `attachment; filename="optimize.sh"`)
			fmt.Fprint(w, optimizeShFile)
			return
		}

		// HTTP 状态页面
		serveStatusPage(w, r, registry, epoll, metrics, startTime)
	})

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *bind, err)
	}
	defer ln.Close()

	log.Printf("[INFO] Status page available at http://%s/", *bind)
	log.Fatal(server.Serve(ln))
}

// handleWsUpgrade 执行 WebSocket 握手并将连接交给 epoll 管理。
func handleWsUpgrade(w http.ResponseWriter, r *http.Request, epoll *Epoll) {
	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return
	}

	// 清除 http.Server 设置的 ReadHeaderTimeout deadline
	conn.SetDeadline(time.Time{})

	fd := socketFd(conn)
	if fd < 0 {
		log.Printf("[WARN] Failed to extract fd from upgraded connection")
		conn.Close()
		return
	}

	c := NewConn(conn, fd)
	if err := epoll.Add(c); err != nil {
		log.Printf("[WARN] epoll.Add failed: %v", err)
		conn.Close()
		return
	}
}

// serveStatusPage 返回服务器状态信息（HTML 或 JSON）。
func serveStatusPage(w http.ResponseWriter, r *http.Request, registry *PeerRegistry, epoll *Epoll, metrics *SystemMetrics, startTime time.Time) {
	if r.URL.Path != "/" && r.URL.Path != "/status" {
		http.NotFound(w, r)
		return
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	uptime := time.Since(startTime).Round(time.Second)

	// JSON 格式: /?json 或 /status?json
	if _, ok := r.URL.Query()["json"]; ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"server":      "KCP-P2P-STUN Signaling Server (Go HP)",
			"version":     "2.0.0",
			"peers":       registry.PeerCount(),
			"conns":       epoll.Count(),
			"heap_mb":     round1(float64(m.HeapInuse) / (1024 * 1024)),
			"sys_mb":      round1(float64(m.Sys) / (1024 * 1024)),
			"uptime":      uptime.String(),
			"uptime_s":    int(uptime.Seconds()),
			"cpu_pct":     round1(metrics.CpuPercent()),
			"mem_avail_mb": round1(metrics.MemAvailMB()),
			"mem_total_mb": round1(metrics.MemTotalMB()),
			"net_up_bps":  metrics.NetUpBPS(),
			"net_down_bps": metrics.NetDownBPS(),
		})
		return
	}

	// HTML 格式（默认）
	optimizeHint := ""
	if v := readSomaxconn(); v >= 0 && v < 65535 {
		optimizeHint = fmt.Sprintf(optimizeScript, v)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, statusHTML,
		registry.PeerCount(),
		epoll.Count(),
		float64(m.HeapInuse)/(1024*1024),
		float64(m.Sys)/(1024*1024),
		uptime,
		metrics.CpuPercent(),
		metrics.MemAvailMB()/1024,
		metrics.MemTotalMB()/1024,
		formatBytesRate(metrics.NetUpBPS()),
		formatBytesRate(metrics.NetDownBPS()),
		optimizeHint,
	)
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

const statusHTML = `<!DOCTYPE html>
<html>
<head><title>KCP-P2P-STUN Signaling Server</title></head>
<body><pre>
KCP-P2P-STUN Signaling Server (Go HP)
========================================
peers       %d
conns       %d
heap        %.1f MB
sys         %.1f MB
uptime      %s

cpu         %.1f%%
mem avail   %.1f / %.1f GB
net up      %s/s
net down    %s/s
%s</pre></body>
</html>
`

const optimizeScript = `
========================================
WARNING: net.core.somaxconn = %d (< 65535)
System is NOT optimized for high concurrency.
Run the following script as root: <a href="/optimize.sh">download optimize.sh</a>
========================================

cat >> /etc/sysctl.conf << 'EOF'
# === Signaling Server Tuning ===
fs.file-max = 2097152
fs.nr_open = 2097152
fs.epoll.max_user_watches = 1048576
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_mem = 786432 1048576 1572864
net.ipv4.tcp_rmem = 4096 4096 16777216
net.ipv4.tcp_wmem = 4096 4096 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
EOF

sysctl -p

cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

echo "Done. Re-login for limits.conf to take effect."
`

const optimizeShFile = `#!/bin/bash
set -e

cat >> /etc/sysctl.conf << 'EOF'
# === Signaling Server Tuning ===
fs.file-max = 2097152
fs.nr_open = 2097152
fs.epoll.max_user_watches = 1048576
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_mem = 786432 1048576 1572864
net.ipv4.tcp_rmem = 4096 4096 16777216
net.ipv4.tcp_wmem = 4096 4096 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
EOF

sysctl -p

cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

echo "Done. Re-login for limits.conf to take effect."
`

// sweeper 定时清理超时连接。统一扫描 epoll connMap，处理所有连接（包括未注册的）。
func sweeper(epoll *Epoll, registry *PeerRegistry, sessions *SessionTracker, interval, maxIdle time.Duration) {
	maxIdleMs := maxIdle.Milliseconds()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		// SweepIdleConns 返回两类连接:
		// - staleConns: 已获取处理权，需要 Close + Release + 业务清理
		// - forcedConns: worker 卡死已 force-close，只需业务清理
		staleConns, forcedConns := epoll.SweepIdleConns(maxIdleMs)

		sweptPeers := 0
		sweptAnon := 0
		for _, c := range staleConns {
			// SweepIdleConns 返回的连接已经 TryAcquire 成功，处理权在 sweeper 手中
			peerID := c.peerID

			c.Close()
			c.Release()

			if peerID != "" {
				sweptPeers++
				registry.Unregister(peerID)
				log.Printf("[WARN] Sweeping stale peer '%s'", peerID)

				related := sessions.RemoveAll(peerID)
				if len(related) > 0 {
					msg := makeMsg("PeerDisconnected", PeerDisconnectedPayload{PeerID: peerID})
					for _, otherPeerID := range related {
						registry.SendTo(otherPeerID, msg)
					}
				}
			} else {
				sweptAnon++
			}
		}

		// 处理 force-closed 连接（worker 卡死，连接已被强制关闭）
		// 不需要 Close/Release（Close 已在 SweepIdleConns 中完成，Release 由 worker 解阻塞后完成）
		forcedPeers := 0
		for _, c := range forcedConns {
			peerID := c.peerID
			if peerID != "" {
				forcedPeers++
				registry.Unregister(peerID)
				log.Printf("[WARN] Force-closing stuck connection for peer '%s'", peerID)

				related := sessions.RemoveAll(peerID)
				if len(related) > 0 {
					msg := makeMsg("PeerDisconnected", PeerDisconnectedPayload{PeerID: peerID})
					for _, otherPeerID := range related {
						registry.SendTo(otherPeerID, msg)
					}
				}
			} else {
				sweptAnon++
			}
		}

		total := sweptPeers + forcedPeers + sweptAnon
		if total > 0 {
			log.Printf("[INFO] Swept %d stale + %d force-closed + %d anonymous, %d peers / %d conns remaining",
				sweptPeers, forcedPeers, sweptAnon, registry.PeerCount(), epoll.Count())
		}
	}
}

// statusPrinter 每 5 分钟打印服务器状态并释放内存回 OS。
func statusPrinter(registry *PeerRegistry, epoll *Epoll, startTime time.Time) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		// 强制 Go runtime 将空闲内存归还给操作系统。
		// Go 默认持有已释放的内存不归还，导致 RSS 持续增长。
		debug.FreeOSMemory()

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Printf("[INFO] Server status: peers=%d, conns=%d, goroutines=%d, heap=%.1fMB, sys=%.1fMB, uptime=%v",
			registry.PeerCount(),
			epoll.Count(),
			runtime.NumGoroutine(),
			float64(m.HeapInuse)/(1024*1024),
			float64(m.Sys)/(1024*1024),
			time.Since(startTime).Round(time.Second))
	}
}
