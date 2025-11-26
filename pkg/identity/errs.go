package identity

import "fmt"

// Address Mismatch Error
type ErrAddressMismatch struct {
	SubjectName            string
	SubjectActualAddress   IdentityAddress
	SubjectExpectedAddress IdentityAddress
}

func (e *ErrAddressMismatch) Error() string {
	return fmt.Sprintf("%s has Address %s but expected %s", e.SubjectName, e.SubjectActualAddress, e.SubjectExpectedAddress)
}
