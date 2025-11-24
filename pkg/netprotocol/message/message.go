package message

import (
	"crypto/ecdh"
	"encoding/binary"
	"io"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type MessageHeader struct {
	IdentityAddress identity.IdentityAddress
	DataLength      uint16
	PrevChainCount  uint8
	ChainCount      uint8
}

type Message struct {
	Header       *MessageHeader
	EphemeralKey *ecdh.PublicKey
	Nonce        [12]byte
	Data         []byte
}

func (m *Message) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, m.Header)
	if err != nil {
		return err
	}

	keyBytes := m.EphemeralKey.Bytes()
	err = binary.Write(w, binary.BigEndian, keyBytes)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, m.Nonce)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, m.Data)
	if err != nil {
		return err
	}

	return nil
}

func Read(r io.Reader) (*Message, error) {
	m := Message{}
	header := MessageHeader{}
	err := binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		return nil, err
	}
	m.Header = &header

	keyBytes := make([]byte, 32)
	err = binary.Read(r, binary.BigEndian, keyBytes)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, &m.Nonce)
	if err != nil {
		return nil, err
	}

	m.Data = make([]byte, m.Header.DataLength)
	err = binary.Read(r, binary.BigEndian, m.Data)
	if err != nil {
		return nil, err
	}

	ephemeralKey, err := ecdh.X25519().NewPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	m.EphemeralKey = ephemeralKey

	return &m, nil
}
