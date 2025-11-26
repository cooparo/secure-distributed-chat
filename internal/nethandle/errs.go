package nethandle

import (
	"fmt"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

// Invalid Receiver Error
type InvalidRecvError struct {
	SubjectName         string
	SubjectActualRecv   identity.IdentityAddress
	SubjectExpectedRecv identity.IdentityAddress
}

func (e *InvalidRecvError) Error() string {
	return fmt.Sprintf("Invalid receiver for %s: %s (expected %s)", e.SubjectName, e.SubjectActualRecv.Base32(), e.SubjectExpectedRecv.Base32())
}

func (e *InvalidRecvError) Unwrap() error {
	return &identity.AddressMismatchError{
		SubjectName:            e.SubjectName,
		SubjectActualAddress:   e.SubjectActualRecv,
		SubjectExpectedAddress: e.SubjectExpectedRecv,
	}
}

// Calculated Address Mismatch Error
type CalcAddrMismatchError struct {
	SubjectActualAddress  identity.IdentityAddress
	SubjectExpectedAddess identity.IdentityAddress
}

func (e *CalcAddrMismatchError) Error() string {
	return fmt.Sprintf("Calculated address %s doesn't match %s", e.SubjectActualAddress, e.SubjectExpectedAddess)
}

func (e *CalcAddrMismatchError) Unwrap() error {
	return &identity.AddressMismatchError{
		SubjectName:            "Address Calculator",
		SubjectActualAddress:   e.SubjectActualAddress,
		SubjectExpectedAddress: e.SubjectExpectedAddess,
	}
}

// Unasked Response Error
type UnaskedResponseError struct {
	SendAddress identity.IdentityAddress
}

func (e *UnaskedResponseError) Error() string {
	return fmt.Sprintf("Unasked response from %s", e.SendAddress.Base32())
}

// No Key Exchange Error
type NoKeyExchangeError struct {
	PeerAddress identity.IdentityAddress
}

func (e *NoKeyExchangeError) Error() string {
	return fmt.Sprintf("No key exchange in process with %s", e.PeerAddress.CheckSize())
}

func (e *NoKeyExchangeError) Unwrap() error {
	return &UnaskedResponseError{
		SendAddress: e.PeerAddress,
	}
}

// No Session Error
type NoSessionError struct {
	PeerAddress identity.IdentityAddress
}

func (e *NoSessionError) Error() string {
	return fmt.Sprintf("No session with %s", e.PeerAddress.Base32())
}
