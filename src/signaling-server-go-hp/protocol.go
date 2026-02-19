package main

import (
	"encoding/json"
	"log"
)

// ============================================================================
// 信令协议消息类型 — 与 Rust p2p-signaling-proto 及原版 Go 服务器完全兼容
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
// 消息构造辅助
// ============================================================================

// 预计算的高频消息，避免热路径上反复 json.Marshal 分配内存。
var (
	pongMsg = []byte(`{"type":"Pong"}`)
)

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
