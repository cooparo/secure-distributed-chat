package kdfchain

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type KDFChain struct {
	KDFKey []byte
	Salt []byte
	Info []byte
}

func (c *KDFChain) Step() ([]byte, error) {
	kdf := hkdf.New(sha256.New, c.KDFKey, c.Salt, c.Info)
	newKDFKey := make([]byte, 32)
	_, err := kdf.Read(newKDFKey)
	if err != nil {
		return nil, err
	}
	outputKey := make([]byte, 32)
	_, err = kdf.Read(outputKey)
	if err != nil {
		return nil, err
	}
	c.KDFKey = newKDFKey
	return outputKey, nil
}
