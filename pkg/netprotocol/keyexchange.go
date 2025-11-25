package netprotocol

import (
	"crypto/ecdh"
	"encoding/binary"
	"io"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type KeyExchangeRequest struct {
	SendIDAddr          identity.IdentityAddress
	RecvIDAddr          identity.IdentityAddress
	SignedKeyBundle     *identity.SignedKeyBundle
	SignedNetAddrUpdate *identity.SignedNetAddressUpdate
	EphemeralKey        *ecdh.PublicKey
	Signature           [64]byte
}

func (req *KeyExchangeRequest) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, req.SendIDAddr)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, req.RecvIDAddr)
	if err != nil {
		return err
	}

	skbByte, err := req.SignedKeyBundle.MarshalBinary()
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, skbByte)
	if err != nil {
		return err
	}

	snauByte, err := req.SignedNetAddrUpdate.MarshalBinary()
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, snauByte)

	err = binary.Write(w, binary.BigEndian, req.EphemeralKey.Bytes())
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, req.Signature)
	if err != nil {
		return err
	}

	return nil
}

func ReadKeyExchangeRequest(r io.Reader) (*KeyExchangeRequest, error) {
	req := KeyExchangeRequest{}
	err := binary.Read(r, binary.BigEndian, req.SendIDAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, req.RecvIDAddr)
	if err != nil {
		return nil, err
	}

	skbByte := make([]byte, identity.SignedKeyBundleSize)
	_, err = r.Read(skbByte)
	if err != nil {
		return nil, err
	}

	var skb identity.SignedKeyBundle
	err = skb.UnmarshalBinary(skbByte)
	if err != nil {
		return nil, err
	}
	req.SignedKeyBundle = &skb

	snauByte := make([]byte, identity.SignedNetAddressUpdateSize)
	_, err = r.Read(snauByte)
	if err != nil {
		return nil, err
	}
	var snau identity.SignedNetAddressUpdate
	err = snau.UnmarshalBinary(snauByte)
	if err != nil {
		return nil, err
	}
	req.SignedNetAddrUpdate = &snau

	ephemeralKeyBytes := make([]byte, 32)
	err = binary.Read(r, binary.BigEndian, ephemeralKeyBytes)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, req.Signature)
	if err != nil {
		return nil, err
	}

	ephemeralKey, err := ecdh.X25519().NewPublicKey(ephemeralKeyBytes)
	if err != nil {
		return nil, err
	}
	req.EphemeralKey = ephemeralKey

	return &req, nil
}

type KeyExchangeResponse struct {
	SendIDAddr   identity.IdentityAddress
	RecvIDAddr   identity.IdentityAddress
	EphemeralKey *ecdh.PublicKey
	RatchetKey   *ecdh.PublicKey
	Signature    [64]byte
}

func (resp *KeyExchangeResponse) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, resp.SendIDAddr)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, resp.RecvIDAddr)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, resp.EphemeralKey.Bytes())
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, resp.RatchetKey.Bytes())
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, resp.Signature)
	if err != nil {
		return err
	}

	return nil
}

func ReadKeyExchangeResponse(r io.Reader) (*KeyExchangeResponse, error) {
	resp := KeyExchangeResponse{}
	err := binary.Read(r, binary.BigEndian, resp.SendIDAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, resp.RecvIDAddr)
	if err != nil {
		return nil, err
	}

	ephemeralKeyBytes := make([]byte, 32)
	err = binary.Read(r, binary.BigEndian, ephemeralKeyBytes)
	if err != nil {
		return nil, err
	}

	ratchetKeyBytes := make([]byte, 32)
	err = binary.Read(r, binary.BigEndian, ratchetKeyBytes)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, resp.Signature)
	if err != nil {
		return nil, err
	}

	ephemeralKey, err := ecdh.X25519().NewPublicKey(ephemeralKeyBytes)
	if err != nil {
		return nil, err
	}
	resp.EphemeralKey = ephemeralKey

	ratchetKey, err := ecdh.X25519().NewPublicKey(ratchetKeyBytes)
	if err != nil {
		return nil, err
	}
	resp.RatchetKey = ratchetKey

	return &resp, nil
}
