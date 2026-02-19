//go:build linux

package main

import (
	"hash/fnv"
	"sync"
)

// SessionTracker 追踪 peer 之间的会话关系（双向兴趣集）。
// 当 peer A 向 peer B 发送信令消息时（ConnectRequest/Answer/Candidate/ReverseConnect），
// 双方互相加入兴趣集。当 A 断连时，只向 A 的兴趣集中的 peer 发送 PeerDisconnected。
//
// 同样使用 256 分片降低锁竞争。分片由 peerID hash 决定。
type SessionTracker struct {
	shards [shardCount]sessionShard
}

type sessionShard struct {
	mu        sync.RWMutex
	interests map[string]map[string]struct{} // peerA → {peerB, peerC, ...}
}

// NewSessionTracker 创建会话追踪器。
func NewSessionTracker() *SessionTracker {
	s := &SessionTracker{}
	for i := range s.shards {
		s.shards[i].interests = make(map[string]map[string]struct{})
	}
	return s
}

func (s *SessionTracker) getShard(peerID string) *sessionShard {
	h := fnv.New32a()
	h.Write([]byte(peerID))
	return &s.shards[h.Sum32()%shardCount]
}

// AddInterest 建立双向兴趣关系：A 关注 B 的状态，B 也关注 A 的状态。
func (s *SessionTracker) AddInterest(peerA, peerB string) {
	if peerA == peerB {
		return
	}
	s.addOneSide(peerA, peerB)
	s.addOneSide(peerB, peerA)
}

func (s *SessionTracker) addOneSide(from, to string) {
	shard := s.getShard(from)
	shard.mu.Lock()
	set, ok := shard.interests[from]
	if !ok {
		set = make(map[string]struct{})
		shard.interests[from] = set
	}
	set[to] = struct{}{}
	shard.mu.Unlock()
}

// RemoveAll 移除 peerID 的所有兴趣关系，并返回其关联的 peer 列表。
// 同时从关联 peer 的兴趣集中移除 peerID。
func (s *SessionTracker) RemoveAll(peerID string) []string {
	// 1. 取出 peerID 的兴趣集
	shard := s.getShard(peerID)
	shard.mu.Lock()
	set := shard.interests[peerID]
	delete(shard.interests, peerID)
	shard.mu.Unlock()

	if len(set) == 0 {
		return nil
	}

	// 2. 收集关联 peer 列表，并从它们的兴趣集中移除 peerID
	related := make([]string, 0, len(set))
	for otherPeerID := range set {
		related = append(related, otherPeerID)
		s.removeOneSide(otherPeerID, peerID)
	}

	return related
}

func (s *SessionTracker) removeOneSide(from, target string) {
	shard := s.getShard(from)
	shard.mu.Lock()
	if set, ok := shard.interests[from]; ok {
		delete(set, target)
		if len(set) == 0 {
			delete(shard.interests, from)
		}
	}
	shard.mu.Unlock()
}
