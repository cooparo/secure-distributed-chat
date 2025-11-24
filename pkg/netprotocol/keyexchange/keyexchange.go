package keyexchange

import (
	"crypto/ecdh"
	"encoding/binary"
	"io"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type Request struct {
	SendIDAddr    identity.IdentityAddress
	RecvIDAddr    identity.IdentityAddress
	KeyBundle     *identity.KeyBundle
	NetAddrUpdate *identity.NetAddrUpdate
	EphemeralKey  *ecdh.PublicKey
	Signature     [64]byte
}

func (req *Request) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, req.SendIDAddr)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, req.RecvIDAddr)
	if err != nil {
		return err
	}

	err = req.KeyBundle.Write(w)
	if err != nil {
		return err
	}

	err = req.NetAddrUpdate.Write(w)
	if err != nil {
		return err
	}

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

func ReadRequest(r io.Reader) (*Request, error) {
	req := Request{}
	err := binary.Read(r, binary.BigEndian, req.SendIDAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, req.RecvIDAddr)
	if err != nil {
		return nil, err
	}

	keyBundle, err := identity.ReadKeyBundle(r)
	if err != nil {
		return nil, err
	}

	req.KeyBundle = keyBundle
	netAddrUpdate, err := identity.ReadNetAddrUpdate(r)
	if err != nil {
		return nil, err
	}
	req.NetAddrUpdate = netAddrUpdate

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

type Response struct {
	RecvIDAddr   identity.IdentityAddress
	SendIDAddr   identity.IdentityAddress
	EphemeralKey *ecdh.PublicKey
	RatchetKey   *ecdh.PublicKey
	Signature    [64]byte
}

func (resp *Response) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, resp.RecvIDAddr)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, resp.SendIDAddr)
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

func ReadResponse(r io.Reader) (*Response, error) {
	resp := Response{}
	err := binary.Read(r, binary.BigEndian, resp.RecvIDAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, resp.SendIDAddr)
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
