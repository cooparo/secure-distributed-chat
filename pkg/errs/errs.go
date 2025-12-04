package errs

import (
	"crypto/ecdh"
	"fmt"
)

// Invalid Size Error
type SizeError struct {
	SubjectName         string
	SubjectActualSize   int
	SubjectExpectedSize int
}

func (e *SizeError) Error() string {
	return fmt.Sprintf("Invalid size of %s: %d (expected %d)", e.SubjectName, e.SubjectActualSize, e.SubjectExpectedSize)
}

// Minimum Size Error
type MinSizeError struct {
	SubjectName         string
	SubjectActualSize   int
	SubjectExpectedSize int
}

func (e *MinSizeError) Error() string {
	return fmt.Sprintf("Size of %s is too small: %d (expected %d)", e.SubjectName, e.SubjectActualSize, e.SubjectExpectedSize)
}

func (e *MinSizeError) Unwrap() error {
	return &SizeError{
		SubjectName:         e.SubjectName,
		SubjectActualSize:   e.SubjectActualSize,
		SubjectExpectedSize: e.SubjectExpectedSize,
	}
}

// Maximum Size Error
type MaxSizeError struct {
	SubjectName         string
	SubjectActualSize   int
	SubjectExpectedSize int
}

func (e *MaxSizeError) Error() string {
	return fmt.Sprintf("Size of %s is too big: %d (expected %d)", e.SubjectName, e.SubjectActualSize, e.SubjectExpectedSize)
}

func (e *MaxSizeError) Unwrap() error {
	return &SizeError{
		SubjectName:         e.SubjectName,
		SubjectActualSize:   e.SubjectActualSize,
		SubjectExpectedSize: e.SubjectExpectedSize,
	}
}

// Diffie-Hellman Curve Error
type DHCurveError struct {
	SubjectName          string
	SubjectActualCurve   ecdh.Curve
	SubjectExpectedCurve ecdh.Curve
}

func (e *DHCurveError) Error() string {
	return fmt.Sprintf("Invalid Diffie-Hellman curve on %s: %s (excepted %s)", e.SubjectName, e.curveName(e.SubjectActualCurve), e.curveName(e.SubjectExpectedCurve))
}

func (e *DHCurveError) curveName(curve ecdh.Curve) string {
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
type IsNilError struct {
	SubjectName string
}

func (e *IsNilError) Error() string {
	return fmt.Sprintf("%s is nil", e.SubjectName)
}

// Verification Error
type VerificationError struct {
	SubjectName string
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s failed verification", e.SubjectName)
}
