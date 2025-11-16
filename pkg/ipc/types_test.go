package ipc

import (
	"bytes"
	"testing"
)

func TestHeaderSerialization(t *testing.T) {
	h := &Header{
		version:          1,
		cmdType:          CmdMsgReq, // 0x00
		cmdPayloadLenght: 256,       // 0x0100
	}

	expectedBytes := []byte{0x01, 0x00, 0x01, 0x00}

	// Test ToBytes
	data, err := h.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes() returned an unexpected error: %v", err)
	}

	if !bytes.Equal(data, expectedBytes) {
		t.Errorf("ToBytes() failed: got %x, want %x", data, expectedBytes)
	}

	// Test FromBytes
	hNew := &Header{}
	if err := hNew.FromBytes(data); err != nil {
		t.Fatalf("FromBytes() returned an unexpected error: %v", err)
	}

	if *h != *hNew {
		t.Errorf("FromBytes() failed: got %+v, want %+v", *hNew, *h)
	}
}

func TestMsgPacketSerialization(t *testing.T) {
	msgPkt := &MsgPacket{
		content: "Hello",
	}

	// content len: 0x0005
	// content ("Hello") = 0x48656c6c6f
	expectedBytes := []byte{0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}

	// ToBytes
	data, err := msgPkt.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes() returned an unexpected error: %v", err)
	}

	if !bytes.Equal(data, expectedBytes) {
		t.Errorf("ToBytes() failed: got %x, want %x", data, expectedBytes)
	}

	// FromBytes
	msgPktNew := &MsgPacket{}
	if _, err := msgPktNew.FromBytes(data); err != nil {
		t.Fatalf("FromBytes() returned an unexpected error: %v", err)
	}

	if msgPkt.content != msgPktNew.content {
		t.Errorf("FromBytes() failed: got content %q, want content %q", msgPktNew.content, msgPkt.content)
	}
}

func TestMsgPacketSerializationTooLarge(t *testing.T) {
	largeBytes := make([]byte, uint32(maxMsgPktSize)+1)
	largeString := string(largeBytes)

	msgPkt := MsgPacket{
		Message(largeString),
	}

	_, err := msgPkt.ToBytes()

	if err == nil {
		t.Error("ToBytes() did not return an error for a message that is too large")
	}
}
