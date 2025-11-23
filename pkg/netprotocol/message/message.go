package message

import (
	"crypto/ecdh"
	"encoding/binary"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
)

type messageHeader struct {
	DataLength     uint16
	PrevChainCount uint8
	ChainCount     uint8
}

func HandleMessage(conn net.Conn) error {
	header := messageHeader{}
	err := binary.Read(conn, binary.BigEndian, &header)
	if err != nil {
		return err
	}

	logger.Get().Debugf("There are %d bytes of encrypted data", header.DataLength)

	logger.Get().Debugf("There was %d messages in the previous chain", header.PrevChainCount)

	logger.Get().Debugf("There is %d messages in this chain", header.ChainCount)

	ephemeralKeyBytes := make([]byte, 32)
	_, err = conn.Read(ephemeralKeyBytes)
	if err != nil {
		return err
	}
	ephemeralKey, err := ecdh.X25519().NewPublicKey(ephemeralKeyBytes)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Got ephemeral ECDH key: %#x", ephemeralKey.Bytes())

	nonce := make([]byte, 12)
	_, err = conn.Read(nonce)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Got nonce: %#x", nonce)

	encryptedData := make([]byte, header.DataLength)
	_, err = conn.Read(encryptedData)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Got encrypted data: %#x", encryptedData)

	return nil
}
