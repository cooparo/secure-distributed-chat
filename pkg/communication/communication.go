package communication

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
)

// Handle the communication on a given connection
func HandleConnection(c net.Conn) {
	defer c.Close()

	err := handlePacket(c)
	if err != nil {
		// Write the error to stderr and end the function
		logger.Get().Error(err.Error())
		return
	}
}

// Handle a incoming packet
func handlePacket(c net.Conn) (error) {
	header := mainHeader{}
	err := binary.Read(c, binary.BigEndian, &header)
	if err != nil {
		return err
	}
	name, ok := packetTypeName[header.PacketType]
	if !ok {
		return fmt.Errorf("Unknown PacketType with id %d", header.PacketType)
	}

	// TODO: Check for the version?
	s := fmt.Sprintf("Got packet with version %d and PacketType %s", header.Version, name)
	logger.Get().Debug(s)

	switch header.PacketType {
	case PacketTypeMessage:
		err := handleMessage(c)
		if err != nil {
			return nil
		}
	default:
		return fmt.Errorf("No handle for PacketType %s", name)
	}

	return nil
}

func handleMessage(c net.Conn) (error) {
	header := messageHeader{}
	err := binary.Read(c, binary.BigEndian, &header)
	if err != nil {
		return err
	}

	s := fmt.Sprintf("The flags are %d", header.Flags)
	logger.Get().Debug(s)

	s = fmt.Sprintf("There are %d bytes of additional associated data", header.AdditionalLength)
	logger.Get().Debug(s)

	s = fmt.Sprintf("There are %d bytes of encrypted data", header.DataLength)
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

	s = fmt.Sprintf("Got ephemeral ECDH key: %x", ephemeralKey.Bytes())
	logger.Get().Debug(s)

	if header.AdditionalLength > 0 {
		additionalData := make([]byte, header.AdditionalLength)
		_, err = c.Read(additionalData)

		s = fmt.Sprintf("Got additional associated data: %s", additionalData)
	}

	nonce := make([]byte, 12)
	_, err = c.Read(nonce)

	s = fmt.Sprintf("Got nonce: %x", nonce)
	logger.Get().Debug(s)

	encryptedData := make([]byte, header.DataLength)

	s = fmt.Sprintf("Got encrypted data: %x", encryptedData)
	if err != nil {
		return err
	}

	return nil
}
