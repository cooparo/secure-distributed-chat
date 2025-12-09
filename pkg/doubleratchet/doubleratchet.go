package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet/kdfchain"
)

type DoubleRatchet struct {
	OurKey    *ecdh.PrivateKey
	TheirKey  *ecdh.PublicKey
	RootChain *kdfchain.RootKDFChain
	SendChain *kdfchain.MsgKDFChain
	RecvChain *kdfchain.MsgKDFChain
}

// Make new DoubleRatchet
// To start with the receiver should set theirKey to nil
// and the sender should have the receivers generated public key
// for theirKey
func New(sharedSecret []byte, theirKey *ecdh.PublicKey) (*DoubleRatchet, error) {
	ourKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	rootChain := kdfchain.RootKDFChain{
		RootKey: sharedSecret,
		Info:    []byte("Root chain for grat"),
	}

	ratchet := DoubleRatchet{
		OurKey:    ourKey,
		TheirKey:  theirKey,
		RootChain: &rootChain,
		SendChain: nil,
		RecvChain: nil,
	}

	// If we have their public key we can step
	// the DH ratchet to get the sending chain
	if theirKey != nil {
		sendChainDH, err := ourKey.ECDH(theirKey)
		if err != nil {
			return nil, err
		}
		sendChainKey, sendNonce, err := rootChain.Step(sendChainDH)
		if err != nil {
			return nil, err
		}

		sendChain := kdfchain.MsgKDFChain{
			ChainKey:     sendChainKey,
			Nonce:        sendNonce,
			MsgCount:     0,
			PrevMsgCount: 0,
		}

		ratchet.SendChain = &sendChain
	}

	return &ratchet, nil
}

// Call when we receive a new ephemeral key
func (r *DoubleRatchet) Update(theirKey *ecdh.PublicKey) error {
	recvChainDH, err := r.OurKey.ECDH(theirKey)
	if err != nil {
		return err
	}

	var recvPrevMsgCount int8 = 0
	if r.RecvChain != nil {
		recvPrevMsgCount = r.RecvChain.MsgCount
	}
	recvChainKey, recvNonce, err := r.RootChain.Step(recvChainDH)
	if err != nil {
		return err
	}

	recvChain := kdfchain.MsgKDFChain{
		ChainKey:     recvChainKey,
		Nonce:        recvNonce,
		MsgCount:     0,
		PrevMsgCount: recvPrevMsgCount,
	}

	ourKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sendChainDH, err := ourKey.ECDH(theirKey)
	if err != nil {
		return err
	}

	var sendPrevMsgCount int8 = 0
	if r.SendChain != nil {
		sendPrevMsgCount = r.SendChain.MsgCount
	}
	sendChainKey, sendNonce, err := r.RootChain.Step(sendChainDH)
	if err != nil {
		return err
	}

	sendChain := kdfchain.MsgKDFChain{
		ChainKey:     sendChainKey,
		Nonce:        sendNonce,
		MsgCount:     0,
		PrevMsgCount: sendPrevMsgCount,
	}

	r.TheirKey = theirKey
	r.OurKey = ourKey
	r.RecvChain = &recvChain
	r.SendChain = &sendChain

	return nil
}

func EncryptedSize(plaintext []byte) int {
	return len(plaintext) + SizeTag
}

func (r *DoubleRatchet) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if r.SendChain == nil {
		return nil, &UninitializedChainError{ChainName: "Sending"}
	}

	key, err := r.SendChain.Step()
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypt(key, r.SendChain.Nonce, plaintext, associatedData)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func (r *DoubleRatchet) Decrypt(theirKey *ecdh.PublicKey, ciphertext, associatedData []byte) ([]byte, error) {

	// TODO: Handle skipped messages

	if r.TheirKey == nil || !r.TheirKey.Equal(theirKey) {
		err := r.Update(theirKey)
		if err != nil {
			return nil, err
		}
	}

	key, err := r.RecvChain.Step()
	if err != nil {
		return nil, err
	}

	plaintext, err := decrypt(key, r.RecvChain.Nonce, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
