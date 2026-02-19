//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// handleSignaling 是消息分发入口，与原版逻辑完全一致。
func handleSignaling(registry *PeerRegistry, sessions *SessionTracker, c *Conn, msg *SignalingMessage) {
	switch msg.Type {
	case "Register":
		handleRegister(registry, c, msg.Payload)
	case "ConnectRequest":
		handleConnectRequest(registry, sessions, c, msg.Payload)
	case "Candidate":
		handleCandidate(registry, sessions, c, msg.Payload)
	case "Answer":
		handleAnswer(registry, sessions, c, msg.Payload)
	case "Reject":
		handleReject(registry, sessions, c, msg.Payload)
	case "ReverseConnect":
		handleReverseConnect(registry, sessions, c, msg.Payload)
	case "Ping":
		c.TrySend(pongMsg)
	case "Unregister":
		if c.peerID != "" {
			registry.Unregister(c.peerID)
			log.Printf("[INFO] Peer '%s' unregistered", c.peerID)
			c.peerID = ""
		}
	default:
		c.TrySend(makeMsgError(ErrInvalidMessage, fmt.Sprintf("Unknown message type: %s", msg.Type)))
	}
}

func handleRegister(registry *PeerRegistry, c *Conn, raw json.RawMessage) {
	var payload RegisterPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.PeerID == "" {
		c.TrySend(makeMsgError(ErrInvalidMessage, "Invalid Register payload"))
		return
	}

	// 如果之前注册了其他 ID，先清理
	if c.peerID != "" {
		registry.Unregister(c.peerID)
	}

	c.peerID = payload.PeerID
	switch registry.Register(payload.PeerID, c) {
	case 2:
		c.peerID = ""
		c.TrySend(makeMsgError(ErrPeerIDTaken, fmt.Sprintf("Peer ID '%s' is already taken", payload.PeerID)))
		return
	}

	serverTime := uint64(time.Now().UnixMilli())
	c.TrySend(makeMsg("Registered", RegisteredPayload{
		PeerID:     payload.PeerID,
		ServerTime: serverTime,
	}))

	log.Printf("[INFO] Peer '%s' registered (v%d) [%d]", payload.PeerID, payload.ProtocolVersion, serverTime)
}

func handleConnectRequest(registry *PeerRegistry, sessions *SessionTracker, c *Conn, raw json.RawMessage) {
	if c.peerID == "" {
		c.TrySend(makeMsgError(ErrNotRegistered, "You must register before connecting"))
		return
	}

	var payload ConnectRequestPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		c.TrySend(makeMsgError(ErrInvalidMessage, "Invalid ConnectRequest payload"))
		return
	}

	// 追踪会话关系
	sessions.AddInterest(c.peerID, payload.TargetPeerID)

	// 转发 IncomingConnection 给目标
	fwd := makeMsg("IncomingConnection", IncomingConnectionPayload{
		FromPeerID: c.peerID,
		SessionID:  payload.SessionID,
	})

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		c.TrySend(makeMsgError(ErrTargetNotFound, fmt.Sprintf("Peer '%s' not found", payload.TargetPeerID)))
		return
	}

	log.Printf("[INFO] ConnectRequest: '%s' -> '%s' (session: %s)", c.peerID, payload.TargetPeerID, payload.SessionID)
}

func handleCandidate(registry *PeerRegistry, sessions *SessionTracker, c *Conn, raw json.RawMessage) {
	if c.peerID == "" {
		c.TrySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload CandidatePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		c.TrySend(makeMsgError(ErrInvalidMessage, "Invalid Candidate payload"))
		return
	}

	// 追踪会话关系
	sessions.AddInterest(c.peerID, payload.TargetPeerID)

	// 转发 CandidateForward 给目标 (保持完整 payload)
	fwd := makeMsg("CandidateForward", payload)

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		c.TrySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
	}
}

func handleAnswer(registry *PeerRegistry, sessions *SessionTracker, c *Conn, raw json.RawMessage) {
	if c.peerID == "" {
		c.TrySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload AnswerPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		c.TrySend(makeMsgError(ErrInvalidMessage, "Invalid Answer payload"))
		return
	}

	// 追踪会话关系
	sessions.AddInterest(c.peerID, payload.TargetPeerID)

	// 转发 AnswerForward 给目标
	fwd := makeMsg("AnswerForward", payload)

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		c.TrySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
		return
	}

	log.Printf("[INFO] Answer: '%s' -> '%s'", c.peerID, payload.TargetPeerID)
}

func handleReject(registry *PeerRegistry, sessions *SessionTracker, c *Conn, raw json.RawMessage) {
	if c.peerID == "" {
		c.TrySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload RejectPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		c.TrySend(makeMsgError(ErrInvalidMessage, "Invalid Reject payload"))
		return
	}

	// 转发 Rejected 给目标
	fwd := makeMsg("Rejected", RejectedPayload{
		FromPeerID: c.peerID,
		SessionID:  payload.SessionID,
		Reason:     payload.Reason,
	})

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		c.TrySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
	}
}

func handleReverseConnect(registry *PeerRegistry, sessions *SessionTracker, c *Conn, raw json.RawMessage) {
	if c.peerID == "" {
		c.TrySend(makeMsgError(ErrNotRegistered, "You must register first"))
		return
	}

	var payload ReverseConnectPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		c.TrySend(makeMsgError(ErrInvalidMessage, "Invalid ReverseConnect payload"))
		return
	}

	// 追踪会话关系
	sessions.AddInterest(c.peerID, payload.TargetPeerID)

	// Forward ReverseConnectForward to target, rewriting target_peer_id to the sender
	fwd := makeMsg("ReverseConnectForward", ReverseConnectPayload{
		TargetPeerID: c.peerID,
		SessionID:    payload.SessionID,
	})

	if !registry.SendTo(payload.TargetPeerID, fwd) {
		c.TrySend(makeMsgError(ErrTargetNotFound, "Target peer not found"))
		return
	}

	log.Printf("[INFO] ReverseConnect: '%s' -> '%s' (session: %s)", c.peerID, payload.TargetPeerID, payload.SessionID)
}
