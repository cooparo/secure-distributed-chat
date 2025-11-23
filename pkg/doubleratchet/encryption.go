package doubleratchet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm, nil
}

func encrypt(key, plaintext, associatedData []byte) ([]byte, []byte, error) {
	aesgcm, err := newAESGCM(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, associatedData)
	return nonce, ciphertext, nil
}

func decrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	aesgcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
