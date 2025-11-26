package identity

import "fmt"

// Address Mismatch Error
type AddressMismatchError struct {
	SubjectName            string
	SubjectActualAddress   IdentityAddress
	SubjectExpectedAddress IdentityAddress
}

func (e *AddressMismatchError) Error() string {
	return fmt.Sprintf("%s has Address %s but expected %s", e.SubjectName, e.SubjectActualAddress, e.SubjectExpectedAddress)
}
