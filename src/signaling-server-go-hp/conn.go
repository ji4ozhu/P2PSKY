package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// Conn 是单个 WebSocket 连接的最小化表示。
// 无 sendCh、无 writer goroutine，写操作通过 writeMu 串行化后直接执行。
type Conn struct {
	netConn    net.Conn   // 底层 TCP 连接（gobwas/ws 读写用）
	fd         int        // 缓存的文件描述符（创建时提取一次，避免反复 reflect）
	peerID     string     // 注册后填入，空串表示未注册
	lastPing   int64      // atomic, UnixMilli — 最后活跃时间
	closed     int32      // atomic bool: 0=open, 1=closed
	processing int32      // atomic bool: 0=空闲, 1=正在被 worker 处理（防止 LT 模式重复分发）
	writeMu    sync.Mutex // 串行化写操作
}

// NewConn 创建一个新连接。fd 在创建时提取并缓存。
func NewConn(netConn net.Conn, fd int) *Conn {
	return &Conn{
		netConn:  netConn,
		fd:       fd,
		lastPing: time.Now().UnixMilli(),
	}
}

// IsClosed 返回连接是否已关闭。
func (c *Conn) IsClosed() bool {
	return atomic.LoadInt32(&c.closed) != 0
}

// Close 标记连接为已关闭并关闭底层 TCP 连接。
// CAS 保证只关闭一次，多次调用安全。
func (c *Conn) Close() {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		c.netConn.Close()
	}
}

// TryAcquire 尝试获取连接的处理权。
// 返回 true 表示获取成功（调用方负责处理完后调用 Release）。
// 返回 false 表示连接正在被其他 worker 处理，应跳过。
func (c *Conn) TryAcquire() bool {
	return atomic.CompareAndSwapInt32(&c.processing, 0, 1)
}

// Release 释放连接的处理权。
func (c *Conn) Release() {
	atomic.StoreInt32(&c.processing, 0)
}

// Touch 更新最后活跃时间。
func (c *Conn) Touch() {
	atomic.StoreInt64(&c.lastPing, time.Now().UnixMilli())
}

// IdleMillis 返回空闲毫秒数。
func (c *Conn) IdleMillis() int64 {
	return time.Now().UnixMilli() - atomic.LoadInt64(&c.lastPing)
}

// Fd 返回缓存的文件描述符。
func (c *Conn) Fd() int {
	return c.fd
}

// WriteMessage 发送一条 WebSocket text 消息。通过 writeMu 保证线程安全。
// 设置 10s 写超时，防止慢客户端阻塞 worker。
func (c *Conn) WriteMessage(data []byte) error {
	if data == nil || c.IsClosed() {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.IsClosed() {
		return nil
	}
	c.netConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return wsutil.WriteServerMessage(c.netConn, ws.OpText, data)
}

// WritePong 发送 WebSocket Pong 帧。
func (c *Conn) WritePong(payload []byte) error {
	if c.IsClosed() {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.IsClosed() {
		return nil
	}
	c.netConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return wsutil.WriteServerMessage(c.netConn, ws.OpPong, payload)
}

// TrySend 尝试发送消息，失败时静默丢弃。
// 不关闭连接 — 关闭必须走 disconnectConn 流程（epoll 移除 + registry 清除 + 通知关联 peer）。
// 如果直接 Close() 会导致：无 log、registry 残留、客户端重连被 "ID already taken" 拒绝。
// 死连接由 sweeper 统一清理。
func (c *Conn) TrySend(data []byte) bool {
	if err := c.WriteMessage(data); err != nil {
		return false
	}
	return true
}

// ReadMessages 从连接读取所有待处理的 WebSocket 消息。
// 不设置读取超时 — SetReadDeadline 会在 WebSocket 帧读取到一半时中断，
// 导致流状态损坏（下次读取字节偏移错位）。
// 对于卡死在半开连接上的 worker，由 sweeper 强制关闭连接来解救。
func (c *Conn) ReadMessages() ([]wsutil.Message, error) {
	return wsutil.ReadClientMessage(c.netConn, nil)
}
