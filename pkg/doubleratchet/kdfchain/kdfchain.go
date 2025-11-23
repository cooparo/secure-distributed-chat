package kdfchain

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type RootKDFChain struct {
	RootKey []byte
	Info    []byte
}

func (c *RootKDFChain) Step(dh []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, dh, c.RootKey, c.Info)
	newRootKey := make([]byte, 32)
	_, err := kdf.Read(newRootKey)
	if err != nil {
		return nil, err
	}
	chainKey := make([]byte, 32)
	_, err = kdf.Read(chainKey)
	c.RootKey = newRootKey
	return chainKey, err
}

type MsgKDFChain struct {
	ChainKey     []byte
	MsgCount     int8
	PrevMsgCount int8
}

func (c *MsgKDFChain) Step() ([]byte, error) {
	kdf := hmac.New(sha256.New, c.ChainKey)
	_, err := kdf.Write([]byte{0x01})
	if err != nil {
		return nil, err
	}
	msgKey := kdf.Sum(nil)
	kdf.Reset()
	_, err = kdf.Write([]byte{0x02})
	if err != nil {
		return nil, err
	}
	c.ChainKey = kdf.Sum(nil)
	c.MsgCount++
	return msgKey, nil
}
