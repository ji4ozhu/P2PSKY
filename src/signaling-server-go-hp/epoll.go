//go:build linux

package main

import (
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Epoll 封装 Linux epoll，管理所有 WebSocket 连接的 fd。
type Epoll struct {
	fd      int          // epoll 实例的 fd
	connMu  sync.RWMutex // 保护 connMap
	connMap map[int]*Conn // fd → Conn
	events  []unix.EpollEvent // 复用的事件缓冲区（仅 Wait 使用，无需锁）
}

// NewEpoll 创建一个新的 epoll 实例。
func NewEpoll() (*Epoll, error) {
	fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &Epoll{
		fd:      fd,
		connMap: make(map[int]*Conn),
		events:  make([]unix.EpollEvent, 1024),
	}, nil
}

// Add 将连接添加到 epoll 监听。
// 使用 EPOLLIN | EPOLLHUP | EPOLLERR，Level Triggered 模式。
func (e *Epoll) Add(c *Conn) error {
	fd := c.Fd()
	if fd < 0 {
		return unix.EBADF
	}
	err := unix.EpollCtl(e.fd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{
		Events: unix.EPOLLIN | unix.EPOLLHUP | unix.EPOLLERR,
		Fd:     int32(fd),
	})
	if err != nil {
		return err
	}
	e.connMu.Lock()
	e.connMap[fd] = c
	e.connMu.Unlock()
	return nil
}

// Remove 从 epoll 中移除连接并从 connMap 删除。
// 安全处理已关闭/不存在的 fd。
func (e *Epoll) Remove(c *Conn) {
	fd := c.Fd()
	if fd < 0 {
		return
	}
	// EpollCtl DEL 可能失败（fd 已关闭），忽略错误
	unix.EpollCtl(e.fd, unix.EPOLL_CTL_DEL, fd, nil)
	e.connMu.Lock()
	delete(e.connMap, fd)
	e.connMu.Unlock()
}

// Wait 阻塞等待 epoll 事件，返回有可读事件的连接列表。
// 复用内部 events 缓冲区，避免热路径上的内存分配。
// 注意: 此方法不是并发安全的，只能由单个 goroutine（reactor 主循环）调用。
func (e *Epoll) Wait() ([]*Conn, error) {
	n, err := unix.EpollWait(e.fd, e.events, -1)
	if err != nil {
		if err == unix.EINTR {
			return nil, nil
		}
		return nil, err
	}

	conns := make([]*Conn, 0, n)
	e.connMu.RLock()
	for i := 0; i < n; i++ {
		fd := int(e.events[i].Fd)
		if c, ok := e.connMap[fd]; ok {
			conns = append(conns, c)
		}
	}
	e.connMu.RUnlock()
	return conns, nil
}

// SweepIdleConns 遍历 connMap，清理超时的空闲连接。
// 返回两个列表:
//   - acquired: 成功获取处理权的空闲连接（调用方负责 Close + Release + 业务清理）
//   - forceClosed: 超长空闲且 worker 卡死的连接（已 force-close + 从 connMap 移除，
//     调用方只需做业务清理，不需要 Close/Release）
//
// force-close 机制：如果连接空闲超过 maxIdleMs + 60s 且 TryAcquire 失败，
// 说明 worker 在此连接上卡死（如半开 TCP）。直接 Close() 会使 worker 的 Read()
// 返回错误并自行退出，避免 worker 永久阻塞。
func (e *Epoll) SweepIdleConns(maxIdleMs int64) (acquired []*Conn, forceClosed []*Conn) {
	forceCloseMs := maxIdleMs + 60000 // 在 maxIdle 基础上再宽限 60s

	e.connMu.Lock()
	for fd, c := range e.connMap {
		idleMs := c.IdleMillis()
		if idleMs <= maxIdleMs {
			continue
		}
		if c.TryAcquire() {
			// 正常路径：获取处理权成功，由调用方 Close + Release
			acquired = append(acquired, c)
			delete(e.connMap, fd)
			unix.EpollCtl(e.fd, unix.EPOLL_CTL_DEL, fd, nil)
		} else if idleMs > forceCloseMs {
			// Worker 卡死路径：强制关闭连接以解救阻塞的 worker。
			// Close() 使 worker 的 Read() 返回 "use of closed connection" 错误，
			// worker 随后调用 disconnectConn → IsClosed() → 早退，最后 Release()。
			c.Close()
			forceClosed = append(forceClosed, c)
			delete(e.connMap, fd)
			unix.EpollCtl(e.fd, unix.EPOLL_CTL_DEL, fd, nil)
		}
		// else: 超时但 worker 正在处理且未超宽限期，跳过，下轮再检查
	}
	e.connMu.Unlock()

	return
}

// Count 返回当前 epoll 管理的连接数。
func (e *Epoll) Count() int {
	e.connMu.RLock()
	defer e.connMu.RUnlock()
	return len(e.connMap)
}

// Close 关闭 epoll 实例。
func (e *Epoll) Close() error {
	return unix.Close(e.fd)
}

// socketFd 从 net.Conn 提取底层文件描述符。
// 使用标准库 syscall.Conn 接口，跨 Go 版本安全。
func socketFd(conn net.Conn) int {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return -1
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return -1
	}
	fd := -1
	raw.Control(func(sysfd uintptr) {
		fd = int(sysfd)
	})
	return fd
}
