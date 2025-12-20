package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestNewWithoutTheirKey(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	if err != nil {
		t.Errorf("Failed to generate shared secret: %s", err.Error())
	}

	ratchet, err := New(sharedSecret, nil)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if ratchet.OurKey == nil {
		t.Error("OurKey found nil, should be initialized")
	}

	if ratchet.TheirKey != nil {
		t.Errorf("TheirKey found %v, should be nil", ratchet.TheirKey)
	}

	if ratchet.RootChain == nil {
		t.Error("RootChain found nil, should be initialized")
	}

	if ratchet.SendChain != nil {
		t.Errorf("SendChain found %v, should be nil when TheirKey is nil", ratchet.SendChain)
	}

	if ratchet.RecvChain != nil {
		t.Errorf("RecvChain found %v, should be nil", ratchet.RecvChain)
	}
}

func TestNewWithTheirKey(t *testing.T) {
	curve := ecdh.X25519()
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	if err != nil {
		t.Errorf("Failed to generate shared secret: %s", err.Error())
	}

	theirPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate their key: %s", err.Error())
	}

	theirPublicKey := theirPrivateKey.PublicKey()

	ratchet, err := New(sharedSecret, theirPublicKey)
	if err != nil {
		t.Errorf("New returned error: %s", err.Error())
	}

	if ratchet.OurKey == nil {
		t.Error("OurKey found nil, should be initialized")
	}

	if ratchet.TheirKey == nil {
		t.Error("TheirKey found nil, should be initialized")
	}

	if ratchet.RootChain == nil {
		t.Error("RootChain found nil, should be initialized")
	}

	if ratchet.SendChain == nil {
		t.Error("RootChain found nil, should be initialized when TheirKey is provided")
	}

	if ratchet.SendChain.MsgCount != 0 {
		t.Errorf("MsgCount found %d, expected 0", ratchet.SendChain.MsgCount)
	}

	if ratchet.SendChain.ChainKey == nil {
		t.Error("SendChain.ChainKey found nil, should be initialized")
	}
}

func TestUpdateInitializesChains(t *testing.T) {
	curve := ecdh.X25519()

	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to generate shared secret: %s", err.Error())
	}

	theirPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to generate their key: %s", err.Error())
	}
	theirPub := theirPriv.PublicKey()

	ratchet, err := New(sharedSecret, nil)
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to create ratchet: %s", err.Error())
	}

	oldOurKey := ratchet.OurKey

	err = ratchet.Update(theirPub)
	if err != nil {
		t.Errorf("Unexpectedy behavior: update returned error: %s", err.Error())
	}

	if ratchet.OurKey == nil {
		t.Error("OurKey found nil after Update")
	}

	if ratchet.OurKey.Equal(oldOurKey) {
		t.Error("OurKey was not rotated")
	}

	if ratchet.TheirKey == nil {
		t.Error("TheirKey found nil after Update")
	}

	if ratchet.SendChain == nil {
		t.Error("SendChain found nil after Update")
	}

	if ratchet.RecvChain == nil {
		t.Error("RecvChain found nil after Update")
	}

	if ratchet.SendChain.MsgCount != 0 {
		t.Errorf("SendChain.MsgCount found %d, expected 0", ratchet.SendChain.MsgCount)
	}

	if ratchet.RecvChain.MsgCount != 0 {
		t.Errorf("RecvChain.MsgCount found %d, expected 0", ratchet.RecvChain.MsgCount)
	}
}

func TestEncryptWithoutSendChainFails(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to generate shared secret: %s", err.Error())
	}

	ratchet, err := New(sharedSecret, nil)
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to create ratchet: %s", err.Error())
	}

	_, err = ratchet.Encrypt([]byte("hello"), nil)
	if err == nil {
		t.Error("Expected error when encrypting without SendChain, got nil")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to generate shared secret: %s", err.Error())
	}

	bob, err := New(sharedSecret, nil)
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to create Bob ratchet: %s", err.Error())
	}

	alice, err := New(sharedSecret, bob.OurKey.PublicKey())
	if err != nil {
		t.Errorf("Unexpectedy behavior: failed to create Alice ratchet: %s", err.Error())
	}

	plaintext := []byte("hello ratchet")
	ad := []byte("associated-data")

	ciphertext, err := alice.Encrypt(plaintext, ad)
	if err != nil {
		t.Errorf("Unexpectedy behavior: encrypt failed: %s", err.Error())
	}

	decrypted, err := bob.Decrypt(alice.OurKey.PublicKey(), ciphertext, ad)
	if err != nil {
		t.Errorf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted plaintext mismatch: got \"%s\", expected \"%s\"", decrypted, plaintext)
	}
}
