package messageprotocol

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
)

type messageHeader struct {
	DataLength uint16
	PrevChainCount uint8
	ChainCount uint8
}

func HandleMessage(c net.Conn) (error) {
	header := messageHeader{}
	err := binary.Read(c, binary.BigEndian, &header)
	if err != nil {
		return err
	}

	s := fmt.Sprintf("There are %d bytes of encrypted data", header.DataLength)
	logger.Get().Debug(s)

	s = fmt.Sprintf("There was %d messages in the previous chain", header.PrevChainCount)
	logger.Get().Debug(s)

	s = fmt.Sprintf("There is %d messages in this chain", header.ChainCount)
	logger.Get().Debug(s)

	ephemeralKeyBytes := make([]byte, 32)
	_, err = c.Read(ephemeralKeyBytes)
	if err != nil {
		return err
	}
	ephemeralKey, err := ecdh.X25519().NewPublicKey(ephemeralKeyBytes)
	if err != nil {
		return err
	}

	s = fmt.Sprintf("Got ephemeral ECDH key: %#x", ephemeralKey.Bytes())
	logger.Get().Debug(s)

	nonce := make([]byte, 12)
	_, err = c.Read(nonce)
	if err != nil {
		return err
	}

	s = fmt.Sprintf("Got nonce: %#x", nonce)
	logger.Get().Debug(s)

	encryptedData := make([]byte, header.DataLength)
	_, err = c.Read(encryptedData)
	if err != nil {
		return err
	}

	s = fmt.Sprintf("Got encrypted data: %#x", encryptedData)
	logger.Get().Debug(s)

	return nil
}
