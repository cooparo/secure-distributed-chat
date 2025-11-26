package identity

import (
	"crypto/ed25519"
	"fmt"
)

// Address Mismatch Error
type AddressMismatchError struct {
	SubjectName            string
	SubjectActualAddress   IdentityAddress
	SubjectExpectedAddress IdentityAddress
}

func (e *AddressMismatchError) Error() string {
	return fmt.Sprintf("%s has address %s but expected %s", e.SubjectName, e.SubjectActualAddress, e.SubjectExpectedAddress)
}

// Verification Error
type VerificationError struct {
	SubjectName string
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s failed verification", e.SubjectName)
}

// Signature Verification Error
type SignatureVerificationError struct {
	SubjectName string
	SigningKey  ed25519.PublicKey
	Signature   Signature
}

func (e *SignatureVerificationError) Error() string {
	return fmt.Sprintf("Failed to verify signature %#x on %s using signing key %#x", e.Signature, e.SubjectName, e.SigningKey)
}

func (e *SignatureVerificationError) Unwrap() error {
	return &VerificationError{
		SubjectName: e.SubjectName,
	}
}
