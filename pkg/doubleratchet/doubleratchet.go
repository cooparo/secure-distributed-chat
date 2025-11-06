package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/cooparo/secure-distributed-chat/pkg/kdfchain"
)

type DoubleRatchet struct {
	OurKey *ecdh.PrivateKey
	TheirKey *ecdh.PublicKey
	RootChain *kdfchain.RootKDFChain
	SendingChain *kdfchain.MessageKDFChain
	ReceiveChain *kdfchain.MessageKDFChain
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
		Info: []byte("Root chain for jchat"),
	}

	ratchet := DoubleRatchet{
		OurKey: ourKey,
		TheirKey: theirKey,
		RootChain: &rootChain,
		SendingChain: nil,
		ReceiveChain: nil,
	}

	// If we have their public key we can step
	// the DH ratchet to get the sending chain
	if theirKey != nil {
		dh, err := ourKey.ECDH(theirKey)
		if err != nil {
			return nil, err
		}
		sendingChainKey, err := rootChain.Step(dh)
		if err != nil {
			return nil, err
		}

		sendingChain := kdfchain.MessageKDFChain{
			ChainKey: sendingChainKey,
		}

		ratchet.SendingChain = &sendingChain
	}

	return &ratchet, nil
}

// Call when we receive a new ephemeral key
// or the receive chain is nil (aka not initialized)
func (r *DoubleRatchet) Receive(theirKey *ecdh.PublicKey) (error) {
	r.TheirKey = theirKey
	receiveChaindh, err := r.OurKey.ECDH(theirKey)
	if err != nil {
		return err
	}

	receiveChainKey, err := r.RootChain.Step(receiveChaindh)
	receiveChain := kdfchain.MessageKDFChain{
		ChainKey: receiveChainKey,
	}
	r.ReceiveChain = &receiveChain

	ourKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	r.OurKey = ourKey
	sendingChaindh, err := ourKey.ECDH(theirKey)
	if err != nil {
		return err
	}

	sendingChainKey, err := r.RootChain.Step(sendingChaindh)
	sendingChain := kdfchain.MessageKDFChain{
		ChainKey: sendingChainKey,
	}
	r.SendingChain = &sendingChain

	return nil
}
