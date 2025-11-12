package keyexchange

import "github.com/cooparo/secure-distributed-chat/pkg/identity"

type exchangeRequest struct {
	SendIDAddr      identity.IdentityAddress
	RecvIDAddr      identity.IdentityAddress
	IDKeyBundle     [128]byte
	IDNetAddrUpdate [24]byte
	EphemeralKey    [32]byte
	Signature       [64]byte
}

type exchangeResponse struct {
	RecvIDAddr   identity.IdentityAddress
	SendIDAddr   identity.IdentityAddress
	EphemeralKey [32]byte
	RatchetKey   [32]byte
	Signature    [64]byte
}
