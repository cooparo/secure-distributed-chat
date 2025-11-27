package kdfchain

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

const (
	SizeRootKey    = 32
	SizeChainKey   = 32
	SizeNonce      = 12
	SizeMessageKey = 32
)

type RootKDFChain struct {
	RootKey []byte
	Info    []byte
}

func (c *RootKDFChain) Step(dh []byte) ([]byte, []byte, error) {
	kdf := hkdf.New(sha256.New, dh, c.RootKey, c.Info)
	newRootKey := make([]byte, SizeRootKey)
	if _, err := kdf.Read(newRootKey); err != nil {
		return nil, nil, err
	}

	chainKey := make([]byte, SizeChainKey)
	if _, err := kdf.Read(chainKey); err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, SizeNonce)
	if _, err := kdf.Read(nonce); err != nil {
		return nil, nil, err
	}

	c.RootKey = newRootKey
	return chainKey, nonce, nil
}

type MsgKDFChain struct {
	ChainKey     []byte
	Nonce        []byte
	MsgCount     int8
	PrevMsgCount int8
}

func (c *MsgKDFChain) Step() ([]byte, error) {
	kdf := hmac.New(sha256.New, c.ChainKey)
	if _, err := kdf.Write([]byte{0x01}); err != nil {
		return nil, err
	}
	msgKey := kdf.Sum(nil)
	kdf.Reset()
	if _, err := kdf.Write([]byte{0x02}); err != nil {
		return nil, err
	}

	c.ChainKey = kdf.Sum(nil)
	c.MsgCount++
	return msgKey, nil
}
