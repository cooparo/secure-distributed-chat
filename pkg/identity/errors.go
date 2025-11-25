package identity

import (
	"crypto/ecdh"
	"fmt"
)

// Invalid Size Error
type ErrInvalidSize struct {
	SubjectName string
	SubjectSize int
}

func (e *ErrInvalidSize) Error() string {
	return fmt.Sprintf("Invalid size of %s: %d", e.SubjectName, e.SubjectSize)
}

// Diffie-Hellman Curve Error
type ErrInvalidCurve struct {
	Curve ecdh.Curve
}

func (e *ErrInvalidCurve) Error() string {
	return fmt.Sprintf("Invalid Diffie-Hellman curve: %s", e.curveName())
}

func (e *ErrInvalidCurve) curveName() string {
	switch e.Curve {
	case ecdh.P256():
		return "P256"
	case ecdh.P384():
		return "P384"
	case ecdh.P521():
		return "P521"
	case ecdh.X25519():
		return "X25519"
	default:
		return "unknown"
	}
}

// Is Nil Error
type ErrIsNil struct {
	SubjectName string
}

func (e *ErrIsNil) Error() string {
	return fmt.Sprintf("%s is nil", e.SubjectName)
}
