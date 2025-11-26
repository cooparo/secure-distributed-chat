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
		sendChainKey, err := rootChain.Step(sendChainDH)
		if err != nil {
			return nil, err
		}

		sendChain := kdfchain.MsgKDFChain{
			ChainKey:     sendChainKey,
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
	recvChainKey, err := r.RootChain.Step(recvChainDH)
	recvChain := kdfchain.MsgKDFChain{
		ChainKey:     recvChainKey,
		MsgCount:     0,
		PrevMsgCount: recvPrevMsgCount,
	}

	ourKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	sendChainDH, err := ourKey.ECDH(theirKey)
	if err != nil {
		return err
	}

	var sendPrevMsgCount int8 = 0
	if r.SendChain != nil {
		sendPrevMsgCount = r.SendChain.MsgCount
	}
	sendChainKey, err := r.RootChain.Step(sendChainDH)
	sendChain := kdfchain.MsgKDFChain{
		ChainKey:     sendChainKey,
		MsgCount:     0,
		PrevMsgCount: sendPrevMsgCount,
	}

	r.TheirKey = theirKey
	r.OurKey = ourKey
	r.RecvChain = &recvChain
	r.SendChain = &sendChain

	return nil
}

func (r *DoubleRatchet) Encrypt(plaintext, associatedData []byte) ([]byte, []byte, error) {
	if r.SendChain == nil {
		return nil, nil, &UninitializedChainError{ChainName: "Sending"}
	}

	key, err := r.SendChain.Step()
	if err != nil {
		return nil, nil, err
	}

	nonce, ciphertext, err := encrypt(key, plaintext, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return nonce, ciphertext, nil
}

func (r *DoubleRatchet) Decrypt(theirKey *ecdh.PublicKey, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	err := r.Update(theirKey)
	if err != nil {
		return nil, err
	}

	key, err := r.RecvChain.Step()
	if err != nil {
		return nil, err
	}

	plaintext, err := decrypt(key, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
