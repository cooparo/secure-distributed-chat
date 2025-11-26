package nethandle

import (
	"fmt"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

// Invalid Receiver Error
type ErrInvalidRecv struct {
	SubjectName         string
	SubjectActualRecv   identity.IdentityAddress
	SubjectExpectedRecv identity.IdentityAddress
}

func (e *ErrInvalidRecv) Error() string {
	return fmt.Sprintf("Invalid receiver for %s: %s (expected %s)", e.SubjectName, e.SubjectActualRecv.Base32(), e.SubjectExpectedRecv.Base32())
}

func (e *ErrInvalidRecv) Unwrap() error {
	return &identity.ErrAddressMismatch{
		SubjectName:            e.SubjectName,
		SubjectActualAddress:   e.SubjectActualRecv,
		SubjectExpectedAddress: e.SubjectExpectedRecv,
	}
}

// Calculated Address Mismatch Error
type ErrCalcAddrMismatch struct {
	SubjectActualAddress  identity.IdentityAddress
	SubjectExpectedAddess identity.IdentityAddress
}

func (e *ErrCalcAddrMismatch) Error() string {
	return fmt.Sprintf("Calculated Address %s doesn't match %s", e.SubjectActualAddress, e.SubjectExpectedAddess)
}

func (e *ErrCalcAddrMismatch) Unwrap() error {
	return &identity.ErrAddressMismatch{
		SubjectName:            "Address Calculator",
		SubjectActualAddress:   e.SubjectActualAddress,
		SubjectExpectedAddress: e.SubjectExpectedAddess,
	}
}
