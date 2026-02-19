//go:build linux

package main

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
)

const shardCount = 256

// PeerRegistry 是分片的 peer 注册表。
// 256 个分片按 peerID hash 分桶，将锁竞争降低 256 倍。
// 无人为容量上限，能跑多少取决于系统资源（fd、内存）。
type PeerRegistry struct {
	shards [shardCount]registryShard
	count  int64 // atomic: 当前 peer 数
}

type registryShard struct {
	mu    sync.RWMutex
	peers map[string]*Conn
}

// NewPeerRegistry 创建注册表。
func NewPeerRegistry() *PeerRegistry {
	r := &PeerRegistry{}
	for i := range r.shards {
		r.shards[i].peers = make(map[string]*Conn)
	}
	return r
}

// getShard 根据 peerID 的 FNV-1a hash 选择分片。
func (r *PeerRegistry) getShard(peerID string) *registryShard {
	h := fnv.New32a()
	h.Write([]byte(peerID))
	return &r.shards[h.Sum32()%shardCount]
}

// Register 注册一个 peer。返回值: 0=成功, 2=ID 已占用（且旧连接仍存活）。
// 如果旧连接已关闭（IsClosed），允许新连接覆盖注册，防止客户端重连时被残留 entry 阻塞。
func (r *PeerRegistry) Register(peerID string, c *Conn) int {
	shard := r.getShard(peerID)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if old, exists := shard.peers[peerID]; exists {
		if !old.IsClosed() {
			return 2 // 旧连接仍存活，拒绝
		}
		// 旧连接已死，允许覆盖（不需要调整 count，数量不变）
		shard.peers[peerID] = c
		return 0
	}

	shard.peers[peerID] = c
	atomic.AddInt64(&r.count, 1)
	return 0
}

// Unregister 移除一个 peer。
func (r *PeerRegistry) Unregister(peerID string) {
	shard := r.getShard(peerID)
	shard.mu.Lock()
	_, existed := shard.peers[peerID]
	delete(shard.peers, peerID)
	shard.mu.Unlock()

	if existed {
		atomic.AddInt64(&r.count, -1)
	}
}

// Lookup 查找 peer 对应的连接。
func (r *PeerRegistry) Lookup(peerID string) (*Conn, bool) {
	shard := r.getShard(peerID)
	shard.mu.RLock()
	c, ok := shard.peers[peerID]
	shard.mu.RUnlock()
	return c, ok
}

// SendTo 向指定 peer 发送消息。返回是否发送成功。
func (r *PeerRegistry) SendTo(peerID string, msg []byte) bool {
	if msg == nil {
		return false
	}
	c, ok := r.Lookup(peerID)
	if !ok || c.IsClosed() {
		return false
	}
	return c.TrySend(msg)
}

// PeerCount 返回当前注册的 peer 数量。O(1) 原子读取。
func (r *PeerRegistry) PeerCount() int {
	return int(atomic.LoadInt64(&r.count))
}
