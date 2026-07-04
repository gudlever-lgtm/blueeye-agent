// Package protocol holds the agent<->server wire-contract constants and the
// frame/message shapes, matching GO-REWRITE-AUDIT.md §1. Wire compatibility
// with the Node server is the acceptance test: identical paths, headers, JSON
// keys and frame vocabulary.
package protocol

// Version is the agent's wire-contract version, declared in the /ws/agent
// upgrade header X-BlueEye-Protocol. MUST equal blueeye-server's PROTOCOL_VERSION.
const Version = 1

// Header names used on both transports.
const (
	HeaderAuthorization = "Authorization"
	HeaderProtocol      = "X-BlueEye-Protocol"
)

// Server -> agent frame types.
const (
	FrameConnected = "connected"
	FrameCommand   = "command"
	// FrameDefinitions carries collector definitions (Go-agent extension; the
	// Node server ignores unknown frames, so requesting/receiving these is
	// additive and backward-compatible).
	FrameDefinitions = "definitions"
)

// Agent -> server frame types.
const (
	FrameHeartbeat          = "heartbeat"
	FrameAck                = "ack"
	FrameCommandResult      = "command-result"
	FrameActionResult       = "action-result"
	FrameSflowStatus        = "sflow.status"
	FrameAgentError         = "agent.error"
	FrameData               = "data" // shadow/metrics data frame (Go-agent extension)
	FrameDefinitionsRequest = "definitions.request"
)

// Connected is the frame the server sends immediately after the WS upgrade.
type Connected struct {
	Type            string `json:"type"`
	AgentID         int64  `json:"agentId"`
	ProtocolVersion int    `json:"protocolVersion"`
}

// Envelope is the minimal shape used to peek at an inbound frame's type before
// decoding the full body.
type Envelope struct {
	Type string `json:"type"`
}

// Heartbeat is the periodic application-level liveness frame.
type Heartbeat struct {
	Type string `json:"type"`
	TS   int64  `json:"ts"`
}
