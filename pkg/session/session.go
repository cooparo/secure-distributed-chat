package session

import (
	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type Session struct {
	Address identity.IdentityAddress
	Ratchet doubleratchet.DoubleRatchet
}

// TODO: Session.Save() method to store in database
