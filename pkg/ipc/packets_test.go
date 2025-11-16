package ipc

// TODO: tests for all packets

import (
	"testing"
)

func TestMsgRespPacketSerialization(t *testing.T) {
	msg1 := MsgPacket{content: "Message 1"}
	msg2 := MsgPacket{content: "Message 2"}
	msg3 := MsgPacket{content: "Message 3"}

	respPkt := NewMsgRespPacket([]MsgPacket{msg1, msg2, msg3})

	// MarshalBinary
	data, err := respPkt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() returned unexpected error: %v", err)
	}

	// UnmarshalBinary
	respPktNew := &MsgRespPacket{}
	if err := respPktNew.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() returned unexpected error: %v", err)
	}

	// Check Header
	if respPkt.header != respPktNew.header {
		t.Errorf("Header mismatch: got %+v, want %+v", respPktNew.header, respPkt.header)
	}

	// Check number of messages
	if len(respPktNew.msgPackets) != len(respPkt.msgPackets) {
		t.Fatalf("Message count mismatch: got %d, want %d", len(respPktNew.msgPackets), len(respPkt.msgPackets))
	}

	// Check content of each message
	for i, originalMsg := range respPkt.msgPackets {
		newMsg := respPktNew.msgPackets[i]
		if originalMsg.content != newMsg.content {
			t.Errorf("Message %d content mismatch: got %q, want %q", i, newMsg.content, originalMsg.content)
		}
	}
}
