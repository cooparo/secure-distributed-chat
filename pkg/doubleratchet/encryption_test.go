package doubleratchet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

const nonceSize = 12

func TestValidEncryption(t *testing.T) {
	key := mustHexToByte(t, "6368616e676520746869732070617373776f726420746f206120736563726574")
	nonce := []byte(strings.Repeat("A", nonceSize))
	plaintext := []byte("exampleplaintext")
	ad := []byte("AAAA")
	exprectedRes := mustHexToByte(t, "2e328e4e7aaf5d8ffb18ee9db45af3fec45e96fe0c20131f9cb5bb56321720f6")

	got, err := encrypt(key, nonce, plaintext, ad)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if !bytes.Equal(exprectedRes, got) {
		t.Errorf("Found %x, expected %x\n", got, exprectedRes)
	}
}

func TestInvalidKeyEncryption(t *testing.T) {
	key := mustHexToByte(t, "0000000000000000000000000000000000000000000000000000000000000000")
	nonce := []byte(strings.Repeat("A", nonceSize))
	plaintext := []byte("exampleplaintext")
	ad := []byte("AAAA")
	expectedRes := mustHexToByte(t, "2e328e4e7aaf5d8ffb18ee9db45af3fec45e96fe0c20131f9cb5bb56321720f6")

	got, err := encrypt(key, nonce, plaintext, ad)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if bytes.Equal(expectedRes, got) {
		t.Errorf("Found %x, expected %x", got, expectedRes)
	}
}

func TestInvalidKeySizeEncryption(t *testing.T) {
	key := mustHexToByte(t, "0000")
	nonce := []byte(strings.Repeat("A", nonceSize))
	plaintext := []byte("exampleplaintext")
	ad := []byte("AAAA")

	_, err := encrypt(key, nonce, plaintext, ad)
	if err == nil {
		t.Error("Unexpected behavior: there should be an error here")
	}
}

func TestInvalidNonceSizeEncryption(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Unexpected behavior: the code should have panicked")
		}
	}()

	key := mustHexToByte(t, "6368616e676520746869732070617373776f726420746f206120736563726574")
	nonce := []byte("AAAA")
	plaintext := []byte("exampleplaintext")
	ad := []byte("AAAA")

	if _, err := encrypt(key, nonce, plaintext, ad); err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
}

func TestValidDecryption(t *testing.T) {
	key := mustHexToByte(t, "6368616e676520746869732070617373776f726420746f206120736563726574")
	nonce := []byte(strings.Repeat("A", nonceSize))
	ciphertext := mustHexToByte(t, "2e328e4e7aaf5d8ffb18ee9db45af3fec45e96fe0c20131f9cb5bb56321720f6")
	ad := []byte("AAAA")
	expectedRes := []byte("exampleplaintext")

	got, err := decrypt(key, nonce, ciphertext, ad)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if !bytes.Equal(expectedRes, got) {
		t.Errorf("Found %x, expected %x", got, expectedRes)
	}
}

func TestInvalidKeyDecryption(t *testing.T) {
	key := mustHexToByte(t, "0000000000000000000000000000000000000000000000000000000000000000")
	nonce := []byte(strings.Repeat("A", nonceSize))
	ciphertext := mustHexToByte(t, "2e328e4e7aaf5d8ffb18ee9db45af3fec45e96fe0c20131f9cb5bb56321720f6")
	ad := []byte("AAAA")

	_, err := decrypt(key, nonce, ciphertext, ad)
	if err == nil {
		t.Error("Unexpected behavior: there should be an error here")
	}
}

func TestInvalidKeySizeDecryption(t *testing.T) {
	key := mustHexToByte(t, "0000")
	nonce := []byte(strings.Repeat("A", nonceSize))
	ciphertext := mustHexToByte(t, "2e328e4e7aaf5d8ffb18ee9db45af3fec45e96fe0c20131f9cb5bb56321720f6")
	ad := []byte("AAAA")

	_, err := decrypt(key, nonce, ciphertext, ad)
	if err == nil {
		t.Error("Unexpected behavior: there should be an error here")
	}
}

func TestInvalidNonceSizeDecryption(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Unexpected behavior: the code should have panicked")
		}
	}()

	key := mustHexToByte(t, "6368616e676520746869732070617373776f726420746f206120736563726574")
	nonce := []byte("AAAA")
	ciphertext := mustHexToByte(t, "2e328e4e7aaf5d8ffb18ee9db45af3fec45e96fe0c20131f9cb5bb56321720f6")
	ad := []byte("AAAA")

	if _, err := decrypt(key, nonce, ciphertext, ad); err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
}

// Helper function
func mustHexToByte(t *testing.T, s string) []byte {
	h, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Invalid hex string in test: %s", s)
	}
	return h
}
