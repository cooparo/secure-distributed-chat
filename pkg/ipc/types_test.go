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

	// Test MarshalBinary
	data, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() returned an unexpected error: %v", err)
	}

	if !bytes.Equal(data, expectedBytes) {
		t.Errorf("MarshalBinary() failed: got %x, want %x", data, expectedBytes)
	}

	// Test UnmarshalBinary
	hNew := &Header{}
	if err := hNew.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() returned an unexpected error: %v", err)
	}

	if *h != *hNew {
		t.Errorf("UnmarshalBinary() failed: got %+v, want %+v", *hNew, *h)
	}
}

func TestMsgPacketSerialization(t *testing.T) {
	msgPkt := &MsgPacket{
		content: "Hello",
	}

	// content len: 0x0005
	// content ("Hello") = 0x48656c6c6f
	expectedBytes := []byte{0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}

	// MarshalBinary
	data, err := msgPkt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() returned an unexpected error: %v", err)
	}

	if !bytes.Equal(data, expectedBytes) {
		t.Errorf("MarshalBinary() failed: got %x, want %x", data, expectedBytes)
	}

	// UnmarshalBinary
	msgPktNew := &MsgPacket{}
	if _, err := msgPktNew.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() returned an unexpected error: %v", err)
	}

	if msgPkt.content != msgPktNew.content {
		t.Errorf("UnmarshalBinary() failed: got content %q, want content %q", msgPktNew.content, msgPkt.content)
	}
}

func TestMsgPacketSerializationTooLarge(t *testing.T) {
	largeBytes := make([]byte, uint32(maxMsgPktSize)+1)
	largeString := string(largeBytes)

	msgPkt := MsgPacket{
		Message(largeString),
	}

	_, err := msgPkt.MarshalBinary()

	if err == nil {
		t.Error("MarshalBinary() did not return an error for a message that is too large")
	}
}
