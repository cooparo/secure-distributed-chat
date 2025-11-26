package errs

import (
	"crypto/ecdh"
	"fmt"
)

// Invalid Size Error
type ErrInvalidSize struct {
	SubjectName         string
	SubjectActualSize   int
	SubjectExpectedSize int
}

func (e *ErrInvalidSize) Error() string {
	return fmt.Sprintf("Invalid size of %s: %d (expected %d)", e.SubjectName, e.SubjectActualSize, e.SubjectExpectedSize)
}

// Minimum Size Error
type ErrMinimumSize struct {
	SubjectName         string
	SubjectActualSize   int
	SubjectExpectedSize int
}

func (e *ErrMinimumSize) Error() string {
	return fmt.Sprintf("Size of %s is too small: %d (expected %d)", e.SubjectName, e.SubjectActualSize, e.SubjectExpectedSize)
}

func (e *ErrMinimumSize) Unwrap() error {
	return &ErrInvalidSize{
		SubjectName:         e.SubjectName,
		SubjectActualSize:   e.SubjectActualSize,
		SubjectExpectedSize: e.SubjectExpectedSize,
	}
}

// Diffie-Hellman Curve Error
type ErrInvalidDHCurve struct {
	SubjectName          string
	SubjectActualCurve   ecdh.Curve
	SubjectExpectedCurve ecdh.Curve
}

func (e *ErrInvalidDHCurve) Error() string {
	return fmt.Sprintf("Invalid Diffie-Hellman curve on %s: %s (excepted %s)", e.SubjectName, e.curveName(e.SubjectActualCurve), e.curveName(e.SubjectExpectedCurve))
}

func (e *ErrInvalidDHCurve) curveName(curve ecdh.Curve) string {
	switch curve {
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
