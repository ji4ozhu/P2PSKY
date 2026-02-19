//go:build linux

package main

import (
	"encoding/json"
	"log"
	"runtime"

	"github.com/gobwas/ws"
)

// Reactor 是 epoll 事件循环 + worker pool 的核心。
type Reactor struct {
	epoll    *Epoll
	registry *PeerRegistry
	sessions *SessionTracker
}

// NewReactor 创建 reactor。
func NewReactor(epoll *Epoll, registry *PeerRegistry, sessions *SessionTracker) *Reactor {
	return &Reactor{
		epoll:    epoll,
		registry: registry,
		sessions: sessions,
	}
}

// Run 启动事件循环。阻塞调用，不会返回。
// 启动 GOMAXPROCS*2 个 worker goroutine 处理消息。
func (r *Reactor) Run() {
	numWorkers := runtime.GOMAXPROCS(0) * 2
	if numWorkers < 8 {
		numWorkers = 8
	}
	// worker 队列容量 = worker 数 × 128
	workCh := make(chan *Conn, numWorkers*128)

	// 启动 worker pool
	for i := 0; i < numWorkers; i++ {
		go r.worker(workCh)
	}

	log.Printf("[INFO] Reactor started: %d workers", numWorkers)

	// 主 epoll 事件循环
	for {
		conns, err := r.epoll.Wait()
		if err != nil {
			log.Printf("[ERROR] epoll.Wait: %v", err)
			continue
		}
		for _, c := range conns {
			if c.IsClosed() {
				// 已关闭的连接（可能被 sweeper 关闭），主动清理残留
				r.epoll.Remove(c)
				continue
			}
			// CAS 获取处理权：防止 LT 模式下同一连接被分发到多个 worker
			if !c.TryAcquire() {
				continue
			}
			// 非阻塞分发到 worker
			select {
			case workCh <- c:
			default:
				// worker 全忙，释放处理权（LT 模式下 epoll 会再次通知）
				c.Release()
			}
		}
	}
}

// worker 从 channel 接收可读连接，读取 WebSocket 消息并处理。
func (r *Reactor) worker(ch <-chan *Conn) {
	for c := range ch {
		r.handleConn(c)
		c.Release()
	}
}

// handleConn 处理单个连接上的所有待读消息。
func (r *Reactor) handleConn(c *Conn) {
	if c.IsClosed() {
		return
	}

	msgs, err := c.ReadMessages()
	if err != nil {
		r.disconnectConn(c)
		return
	}

	for _, msg := range msgs {
		if msg.OpCode == ws.OpClose {
			r.disconnectConn(c)
			return
		}
		if msg.OpCode == ws.OpText {
			c.Touch()
			r.handleTextMessage(c, msg.Payload)
		}
		if msg.OpCode == ws.OpPing {
			c.Touch()
			c.WritePong(msg.Payload)
		}
		if msg.OpCode == ws.OpPong {
			c.Touch()
		}
	}
}

// handleTextMessage 解析并处理一条 JSON 信令消息。
func (r *Reactor) handleTextMessage(c *Conn, data []byte) {
	var msg SignalingMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		c.TrySend(makeMsgError(ErrInvalidMessage, "Invalid JSON"))
		return
	}
	handleSignaling(r.registry, r.sessions, c, &msg)
}

// disconnectConn 处理连接断开：从 epoll 移除、关闭 fd、从注册表移除、通知关联 peer。
func (r *Reactor) disconnectConn(c *Conn) {
	if c.IsClosed() {
		return
	}

	peerID := c.peerID

	// 1. 先从 epoll 移除（防止后续事件触发）
	r.epoll.Remove(c)

	// 2. 关闭连接（CAS 保证只执行一次）
	c.Close()

	// 3. 从注册表移除并通知关联 peer
	if peerID != "" {
		r.registry.Unregister(peerID)
		log.Printf("[INFO] Peer '%s' disconnected", peerID)

		related := r.sessions.RemoveAll(peerID)
		if len(related) > 0 {
			msg := makeMsg("PeerDisconnected", PeerDisconnectedPayload{PeerID: peerID})
			for _, otherPeerID := range related {
				r.registry.SendTo(otherPeerID, msg)
			}
		}
	}
}
