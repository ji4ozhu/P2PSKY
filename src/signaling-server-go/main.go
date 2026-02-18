package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================================
// 信令协议消息类型 — 与 Rust p2p-signaling-proto 完全兼容
// ============================================================================

// SignalingMessage 顶层消息 (serde tagged enum 格式: {"type":"X","payload":{...}})
type SignalingMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type RegisterPayload struct {
	PeerID          string `json:"peer_id"`
	ProtocolVersion uint32 `json:"protocol_version"`
}

type RegisteredPayload struct {
	PeerID     string `json:"peer_id"`
	ServerTime uint64 `json:"server_time"`
}

type ConnectRequestPayload struct {
	TargetPeerID string `json:"target_peer_id"`
	SessionID    string `json:"session_id"`
}

type IncomingConnectionPayload struct {
	FromPeerID string `json:"from_peer_id"`
	SessionID  string `json:"session_id"`
}

// CandidatePayload — 直接透传，不解析 candidate 内部结构
type CandidatePayload struct {
	TargetPeerID string          `json:"target_peer_id"`
	SessionID    string          `json:"session_id"`
	Candidate    json.RawMessage `json:"candidate"`
}

type AnswerPayload struct {
	TargetPeerID string `json:"target_peer_id"`
	SessionID    string `json:"session_id"`
}

type RejectPayload struct {
	TargetPeerID string `json:"target_peer_id"`
	SessionID    string `json:"session_id"`
	Reason       string `json:"reason"`
}

type RejectedPayload struct {
	FromPeerID string `json:"from_peer_id"`
	SessionID  string `json:"session_id"`
	Reason     string `json:"reason"`
}

type ReverseConnectPayload struct {
	TargetPeerID string `json:"target_peer_id"`
	SessionID    string `json:"session_id"`
}

type PeerDisconnectedPayload struct {
	PeerID string `json:"peer_id"`
}

type ErrorPayload struct {
	Code    uint32 `json:"code"`
	Message string `json:"message"`
}

// 错误码
const (
	ErrPeerIDTaken    = 1001
	ErrTargetNotFound = 1002
	ErrNotRegistered  = 1003
	ErrInvalidMessage = 1004
	ErrServerFull     = 1005
)

// ============================================================================
// Peer 注册表
// ============================================================================

type PeerRegistry struct {
	mu       sync.RWMutex
	peers    map[string]*PeerConn
	maxPeers int
}

type PeerConn struct {
	conn       *websocket.Conn
	sendCh     chan []byte
	peerID     string
	lastActive atomic.Int64
	closed     atomic.Bool
}

// trySend 非阻塞发送消息到 sendCh。
// 如果缓冲区满则丢弃消息并返回 false，防止读循环阻塞导致 goroutine 泄漏。
// L3: Returns false for nil messages (failed serialization).
func (pc *PeerConn) trySend(msg []byte) bool {
	if msg == nil {
		return false
	}
	if pc.closed.Load() {
		return false
	}
	select {
	case pc.sendCh <- msg:
		return true
	default:
		log.Printf("[WARN] sendCh full for peer '%s', dropping message", pc.peerID)
		return false
	}
}

func NewRegistry(maxPeers int) *PeerRegistry {
	return &PeerRegistry{
		peers:    make(map[string]*PeerConn),
		maxPeers: maxPeers,
	}
}

// Register returns 0 on success, 1 if the server is full, 2 if the peer ID is taken.
func (r *PeerRegistry) Register(peerID string, pc *PeerConn) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.peers) >= r.maxPeers {
		return 1
	}
	if _, exists := r.peers[peerID]; exists {
		return 2
	}
	r.peers[peerID] = pc
	return 0
}

func (r *PeerRegistry) Unregister(peerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, peerID)
}

func (r *PeerRegistry) SendTo(peerID string, msg []byte) bool {
	if msg == nil {
		return false
	}
	r.mu.RLock()
	pc, ok := r.peers[peerID]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	if pc.closed.Load() {
		return false
	}
	select {
	case pc.sendCh <- msg:
		return true
	default:
		// 发送缓冲区满，丢弃
		return false
	}
}

func (r *PeerRegistry) PeerCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// BroadcastPeerDisconnected 通知所有在线 peer 某 peer 已下线
func (r *PeerRegistry) BroadcastPeerDisconnected(disconnectedPeerID string) {
	msg := makeMsg("PeerDisconnected", PeerDisconnectedPayload{PeerID: disconnectedPeerID})
	if msg == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, pc := range r.peers {
		if pc.closed.Load() {
			continue
		}
		select {
		case pc.sendCh <- msg:
		default:
		}
	}
}

// SweepStale 强制关闭超过 maxIdle 没有活动的连接，防止僵尸连接泄漏 FD。
func (r *PeerRegistry) SweepStale(maxIdle time.Duration) int {
	nowMs := time.Now().UnixMilli()
	r.mu.Lock()
	var stale []*PeerConn
	for id, pc := range r.peers {
		if time.Duration(nowMs-pc.lastActive.Load())*time.Millisecond > maxIdle {
			stale = append(stale, pc)
			delete(r.peers, id)
		}
	}
	r.mu.Unlock()

	for _, pc := range stale {
		idleMs := nowMs - pc.lastActive.Load()
		log.Printf("[WARN] Sweeping stale peer '%s' (idle %v)", pc.peerID, (time.Duration(idleMs)*time.Millisecond).Round(time.Second))
		pc.conn.Close() // 强制关闭，触发读循环退出 + writePump 退出
	}
	return len(stale)
}

// StartSweeper 启动后台定时清理
func (r *PeerRegistry) StartSweeper(interval, maxIdle time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			swept := r.SweepStale(maxIdle)
			if swept > 0 {
				log.Printf("[INFO] Swept %d stale peers, %d remaining", swept, r.PeerCount())
			}
		}
	}()
}

// ============================================================================
// 消息构造辅助
// ============================================================================

func makeMsg(msgType string, payload interface{}) []byte {
	p, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[ERROR] json.Marshal payload failed for %s: %v", msgType, err)
		return nil
	}
	m := SignalingMessage{Type: msgType, Payload: p}
	data, err := json.Marshal(m)
	if err != nil {
		log.Printf("[ERROR] json.Marshal message failed for %s: %v", msgType, err)
		return nil
	}
	return data
}

func makeMsgSimple(msgType string) []byte {
	data, err := json.Marshal(map[string]string{"type": msgType})
	if err != nil {
		log.Printf("[ERROR] json.Marshal simple message failed for %s: %v", msgType, err)
		return nil
	}
	return data
}

func makeMsgError(code uint32, message string) []byte {
	msg := makeMsg("Error", ErrorPayload{Code: code, Message: message})
	if msg == nil {
		log.Printf("[ERROR] Failed to construct error message: code=%d, msg=%s", code, message)
	}
	return msg
}

// ============================================================================
// WebSocket 连接处理
// ============================================================================

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func handleWebSocket(registry *PeerRegistry, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WARN] Upgrade failed: %v", err)
		return
	}

	pc := &PeerConn{
		conn:   conn,
		sendCh: make(chan []byte, 256),
	}
	pc.lastActive.Store(time.Now().UnixMilli())

	// 启动写协程
	go writePump(pc)

	// 读循环
	defer func() {
		if pc.peerID != "" {
			registry.Unregister(pc.peerID)
			log.Printf("[INFO] Peer '%s' disconnected", pc.peerID)
			registry.BroadcastPeerDisconnected(pc.peerID)
		}
		pc.closed.Store(true)
		close(pc.sendCh)
		conn.Close()
	}()

	conn.SetReadLimit(1 << 20) // 1MB
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		pc.lastActive.Store(time.Now().UnixMilli())
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[WARN] Read error: %v", err)
			}
			break
		}

		pc.lastActive.Store(time.Now().UnixMilli())
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		var msg SignalingMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			pc.trySend(makeMsgError(ErrInvalidMessage, "Invalid JSON"))
			continue
		}

		handleSignaling(registry, pc, &msg)
	}
}

func writePump(pc *PeerConn) {
	ticker := time.NewTicker(25 * time.Second) // WebSocket Ping 间隔
	defer func() {
		ticker.Stop()
		// 关键: writePump 退出时关闭连接，强制读循环也退出
		pc.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-pc.sendCh:
			if !ok {
				// channel 已关闭 (读循环 defer 触发)
				pc.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			pc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := pc.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			pc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := pc.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ============================================================================
// 信令消息处理
// ============================================================================

func handleSignaling(registry *PeerRegistry, pc *PeerConn, msg *SignalingMessage) {
	switch msg.Type {
	case "Register":
		handleRegister(registry, pc, msg.Payload)
	case "ConnectRequest":
		handleConnectRequest(registry, pc, msg.Payload)
	case "Candidate":
		handleCandidate(registry, pc, msg.Payload)
	case "Answer":
		handleAnswer(registry, pc, msg.Payload)
	case "Reject":
		handleReject(registry, pc, msg.Payload)
	case "ReverseConnect":
		handleReverseConnect(registry, pc, msg.Payload)
	case "Ping":
		pc.trySend(makeMsgSimple("Pong"))
	case "Unregister":
		if pc.peerID != "" {
			registry.Unregister(pc.peerID)
			log.Printf("[INFO] Peer '%s' unregistered", pc.peerID)
			pc.peerID = ""
		}
	default:
		pc.trySend(makeMsgError(ErrInvalidMessage, fmt.Sprintf("Unknown message type: %s", msg.Type)))
	}
}

func handleRegister(registry *PeerRegistry, pc *PeerConn, raw json.RawMessage) {
	var payload RegisterPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.PeerID == "" {
		pc.trySend(makeMsgError(ErrInvalidMessage, "Invalid Register payload"))
		return
	}

	// 如果之前注册了其他 ID，先清理
	if pc.peerID != "" {
		registry.Unregister(pc.peerID)
	}

	pc.peerID = payload.PeerID
	switch registry.Register(payload.PeerID, pc) {
	case 1:
		pc.peerID = ""
		pc.trySend(makeMsgError(ErrServerFull, "Server is full"))
		return
	case 2:
		pc.peerID = ""
		pc.trySend(makeMsgError(ErrPeerIDTaken, fmt.Sprintf("Peer ID '%s' is already taken", payload.PeerID)))
		return
	}

	serverTime := uint64(time.Now().UnixMilli())
	pc.trySend(makeMsg("Registered", RegisteredPayload{
		PeerID:     payload.PeerID,
		ServerTime: serverTime,
	}))

	log.Printf("[INFO] Peer '%s' registered (v%d) [%d]", payload.PeerID, payload.ProtocolVersion, serverTime)
}

func handleConnectRequest(registry *PeerRegistry, pc *PeerConn, raw json.RawMessage) {
	if pc.peerID == "" {
		pc.trySend(makeMsgError(ErrNotRegistered, "You must register before connecting"))
		return
	}

	var payload ConnectRequestPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		pc.trySend(makeMsgError(ErrInvalidMessage, "Invalid ConnectRequest payload"))
		return
	}

	// 转发 IncomingConnection 给目标
	fwd := makeMsg("IncomingConnection", IncomingConnectionPayload{
		FromPeerID: pc.peerID,
		SessionID:  payload.SessionID,
	})

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		pc.trySend(makeMsgError(ErrTargetNotFound, fmt.Sprintf("Peer '%s' not found", payload.TargetPeerID)))
		return
	}

	log.Printf("[INFO] ConnectRequest: '%s' -> '%s' (session: %s)", pc.peerID, payload.TargetPeerID, payload.SessionID)
}

func handleCandidate(registry *PeerRegistry, pc *PeerConn, raw json.RawMessage) {
	if pc.peerID == "" {
		pc.trySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload CandidatePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		pc.trySend(makeMsgError(ErrInvalidMessage, "Invalid Candidate payload"))
		return
	}

	// 转发 CandidateForward 给目标 (保持完整 payload)
	fwd := makeMsg("CandidateForward", payload)

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		pc.trySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
	}
}

func handleAnswer(registry *PeerRegistry, pc *PeerConn, raw json.RawMessage) {
	if pc.peerID == "" {
		pc.trySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload AnswerPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		pc.trySend(makeMsgError(ErrInvalidMessage, "Invalid Answer payload"))
		return
	}

	// 转发 AnswerForward 给目标
	fwd := makeMsg("AnswerForward", payload)

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		pc.trySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
		return
	}

	log.Printf("[INFO] Answer: '%s' -> '%s'", pc.peerID, payload.TargetPeerID)
}

func handleReject(registry *PeerRegistry, pc *PeerConn, raw json.RawMessage) {
	if pc.peerID == "" {
		pc.trySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload RejectPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		pc.trySend(makeMsgError(ErrInvalidMessage, "Invalid Reject payload"))
		return
	}

	// 转发 Rejected 给目标
	fwd := makeMsg("Rejected", RejectedPayload{
		FromPeerID: pc.peerID,
		SessionID:  payload.SessionID,
		Reason:     payload.Reason,
	})

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		pc.trySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
	}
}

func handleReverseConnect(registry *PeerRegistry, pc *PeerConn, raw json.RawMessage) {
	if pc.peerID == "" {
		pc.trySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload ReverseConnectPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		pc.trySend(makeMsgError(ErrInvalidMessage, "Invalid ReverseConnect payload"))
		return
	}

	// Forward ReverseConnectForward to target, rewriting target_peer_id to the sender
	fwd := makeMsg("ReverseConnectForward", ReverseConnectPayload{
		TargetPeerID: pc.peerID,
		SessionID:    payload.SessionID,
	})

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		pc.trySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
		return
	}

	log.Printf("[INFO] ReverseConnect: '%s' -> '%s' (session: %s)", pc.peerID, payload.TargetPeerID, payload.SessionID)
}

// ============================================================================
// HTTP 状态页
// ============================================================================

func handleStatus(registry *PeerRegistry, startTime time.Time, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"server":  "KCP-P2P-STUN Signaling Server (Go)",
		"peers":   registry.PeerCount(),
		"uptime":  int(time.Since(startTime).Seconds()),
		"version": "1.0.0",
	})
}

// ============================================================================
// main
// ============================================================================

func main() {
	bind := flag.String("bind", "0.0.0.0:8080", "Bind address (host:port)")
	maxPeers := flag.Int("max-peers", 10000, "Maximum concurrent peers")
	flag.Parse()

	registry := NewRegistry(*maxPeers)
	startTime := time.Now()

	// 启动后台清理: 每 30 秒扫描一次，踢掉 120 秒没活动的 peer
	registry.StartSweeper(30*time.Second, 120*time.Second)

	// 定时打印服务器状态
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("[INFO] Server status: peers=%d, uptime=%v",
				registry.PeerCount(),
				time.Since(startTime).Round(time.Second))
		}
	}()

	fmt.Println("============================================")
	fmt.Println(" KCP-P2P-STUN Signaling Server (Go)")
	fmt.Println("============================================")
	fmt.Printf("  Bind:      %s\n", *bind)
	fmt.Printf("  Max peers: %d\n", *maxPeers)
	fmt.Println("============================================")
	fmt.Println("Listening...")
	fmt.Println()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			handleWebSocket(registry, w, r)
		} else {
			handleStatus(registry, startTime, w, r)
		}
	})

	server := &http.Server{
		Addr:              *bind,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // 防止慢速 HTTP 握手挂死
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second, // 非 WebSocket 空闲连接超时
	}

	log.SetFlags(log.Ldate | log.Ltime)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe failed: %v", err)
	}
}
