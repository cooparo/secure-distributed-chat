package netprotocol

import (
	"fmt"

	"github.com/cooparo/secure-distributed-chat/pkg/common/flags"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeFullIdentity            = identity.SizeIdentityAddress + identity.SizeSignedKeyBundle + identity.SizeSignedNetworkUpdate
	SizeIdentityCount           = 1
	SizeMaxIdentityCount        = 1
	SizeDiscoveryRequestHeader  = identity.SizeIdentityAddress + identity.SizeSignedKeyBundle + identity.SizeSignedNetworkUpdate + identity.SizeIdentityAddress + SizeIdentityCount + SizeMaxIdentityCount
	SizeFlags                   = 1
	SizeDiscoveryResponseHeader = identity.SizeIdentityAddress + SizeFlags + SizeIdentityCount
)

const (
	FlagDiscHit flags.Flags = 1 << iota
)

type FullIdentity struct {
	Address             identity.IdentityAddress
	SignedKeyBundle     *identity.SignedKeyBundle
	SignedNetworkUpdate *identity.SignedNetworkUpdate
}

func (fullid *FullIdentity) AppendBinary(b []byte) ([]byte, error) {
	if err := fullid.Address.CheckSize(); err != nil {
		return nil, err
	}
	if fullid.SignedKeyBundle == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedKeyBundle"}
	}
	if fullid.SignedNetworkUpdate == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedNetworkUpdate"}
	}

	// Encode Address
	b = append(b, fullid.Address...)

	// Encode SignedKeyBundle
	b, err := fullid.SignedKeyBundle.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode SignedNetworkUpdate
	b, err = fullid.SignedNetworkUpdate.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (fullid *FullIdentity) MarshalBinary() ([]byte, error) {
	b, err := fullid.AppendBinary(make([]byte, 0, SizeFullIdentity))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (fullid *FullIdentity) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeFullIdentity {
		return &errs.SizeError{
			SubjectName:         "FullIdentity",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeFullIdentity,
		}
	}

	// Decode Address
	fullid.Address = make([]byte, identity.SizeIdentityAddress)
	copy(fullid.Address, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode SignedKeyBundle
	sigkeybndlByte := make([]byte, identity.SizeSignedKeyBundle)
	copy(sigkeybndlByte, buf[:identity.SizeSignedKeyBundle])
	sigkeybndl := &identity.SignedKeyBundle{}
	if err := sigkeybndl.UnmarshalBinary(sigkeybndlByte); err != nil {
		return err
	}
	fullid.SignedKeyBundle = sigkeybndl

	buf = buf[identity.SizeSignedKeyBundle:]

	// Decode SignedNetworkUpdate
	signetupdByte := make([]byte, identity.SizeSignedNetworkUpdate)
	copy(signetupdByte, buf[:identity.SizeSignedNetworkUpdate])
	signetupd := &identity.SignedNetworkUpdate{}
	if err := signetupd.UnmarshalBinary(signetupdByte); err != nil {
		return err
	}
	fullid.SignedNetworkUpdate = signetupd

	return nil
}

type DiscoveryRequestHeader struct {
	SendIDAddr          identity.IdentityAddress
	SignedKeyBundle     *identity.SignedKeyBundle
	SignedNetworkUpdate *identity.SignedNetworkUpdate
	LookupIDAddr        identity.IdentityAddress
	IdentityCount       uint8
	MaxIdentityCount    uint8
}

func (discreqhdr *DiscoveryRequestHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := discreqhdr.SendIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if discreqhdr.SignedKeyBundle == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedKeyBundle"}
	}
	if discreqhdr.SignedNetworkUpdate == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedNetAddressUpdate"}
	}
	if err := discreqhdr.LookupIDAddr.CheckSize(); err != nil {
		return nil, err
	}

	// Encode SendIDAddr
	b = append(b, discreqhdr.SendIDAddr...)

	// Encode SignedKeyBundle
	b, err := discreqhdr.SignedKeyBundle.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode SignedNetworkUpdate
	b, err = discreqhdr.SignedNetworkUpdate.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode LookupIDAddr
	b = append(b, discreqhdr.LookupIDAddr...)

	// Encode IdentityCount
	idCount := discreqhdr.IdentityCount
	b = append(b, byte(idCount))

	// Encode MaxIdentityCount
	maxIdCount := discreqhdr.MaxIdentityCount
	b = append(b, byte(maxIdCount))

	return b, nil
}

func (discreqhdr *DiscoveryRequestHeader) MarshalBinary() ([]byte, error) {
	b, err := discreqhdr.AppendBinary(make([]byte, 0, SizeDiscoveryRequestHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (discreqhdr *DiscoveryRequestHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeDiscoveryRequestHeader {
		return &errs.SizeError{
			SubjectName:         "DiscoveryRequestHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeDiscoveryRequestHeader,
		}
	}

	// Decode SendIDAddr
	discreqhdr.SendIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(discreqhdr.SendIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode SignedKeyBundle
	sigkeybndlByte := make([]byte, identity.SizeSignedKeyBundle)
	copy(sigkeybndlByte, buf[:identity.SizeSignedKeyBundle])
	sigkeybndl := &identity.SignedKeyBundle{}
	if err := sigkeybndl.UnmarshalBinary(sigkeybndlByte); err != nil {
		return err
	}
	discreqhdr.SignedKeyBundle = sigkeybndl

	buf = buf[identity.SizeSignedKeyBundle:]

	// Decode SignedNetworkUpdate
	signetupdByte := make([]byte, identity.SizeSignedNetworkUpdate)
	copy(signetupdByte, buf[:identity.SizeSignedNetworkUpdate])
	signetupd := &identity.SignedNetworkUpdate{}
	if err := signetupd.UnmarshalBinary(signetupdByte); err != nil {
		return err
	}
	discreqhdr.SignedNetworkUpdate = signetupd

	buf = buf[identity.SizeSignedNetworkUpdate:]

	// Decode LookupIDAddr
	discreqhdr.LookupIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(discreqhdr.LookupIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode IdentityCount
	discreqhdr.IdentityCount = uint8(buf[0])

	buf = buf[SizeIdentityCount:]

	// Decode MaxIdentityCount
	discreqhdr.MaxIdentityCount = uint8(buf[0])

	return nil
}

type DiscoveryRequest struct {
	Header               *DiscoveryRequestHeader
	AdditionalIdentities []*FullIdentity
}

func (discreq *DiscoveryRequest) AppendBinary(b []byte) ([]byte, error) {
	if discreq.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	if len(discreq.AdditionalIdentities) != int(discreq.Header.IdentityCount) {
		return nil, &errs.SizeError{
			SubjectName:         "AdditionalIdentities",
			SubjectActualSize:   len(discreq.AdditionalIdentities),
			SubjectExpectedSize: int(discreq.Header.IdentityCount),
		}
	}

	// Encode Header
	b, err := discreq.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode AdditionalIdentities
	for idx, fullid := range discreq.AdditionalIdentities {
		if fullid == nil {
			return nil, &errs.IsNilError{SubjectName: fmt.Sprintf("AdditionalIdentities[%d]", idx)}
		}
		b, err = fullid.AppendBinary(b)
		if err != nil {
			return nil, err
		}
	}

	return b, nil
}

func (discreq *DiscoveryRequest) MarshalBinary() ([]byte, error) {
	if discreq.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	sizeDiscoveryRequest := SizeDiscoveryRequestHeader + (int(discreq.Header.IdentityCount) * SizeFullIdentity)
	b, err := discreq.AppendBinary(make([]byte, 0, sizeDiscoveryRequest))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (discreq *DiscoveryRequest) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < SizeDiscoveryRequestHeader {
		return &errs.MinSizeError{
			SubjectName:         "DiscoveryRequest",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeDiscoveryRequestHeader,
		}
	}

	// Decode Header
	discreqhdrByte := make([]byte, SizeDiscoveryRequestHeader)
	copy(discreqhdrByte, buf[:SizeDiscoveryRequestHeader])
	discreqhdr := &DiscoveryRequestHeader{}
	if err := discreqhdr.UnmarshalBinary(discreqhdrByte); err != nil {
		return err
	}
	discreq.Header = discreqhdr

	buf = buf[SizeDiscoveryRequestHeader:]

	sizeAdditionalIdentities := int(discreqhdr.IdentityCount) * SizeFullIdentity
	if len(buf) != sizeAdditionalIdentities {
		return &errs.SizeError{
			SubjectName:         "AdditionalIdentities",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: sizeAdditionalIdentities,
		}
	}

	// Decode AdditionalIdentities
	discreq.AdditionalIdentities = make([]*FullIdentity, 0, discreqhdr.IdentityCount)
	for range discreqhdr.IdentityCount {
		fullidByte := make([]byte, SizeFullIdentity)
		copy(fullidByte, buf[:SizeFullIdentity])
		fullid := &FullIdentity{}
		if err := fullid.UnmarshalBinary(fullidByte); err != nil {
			return err
		}
		discreq.AdditionalIdentities = append(discreq.AdditionalIdentities, fullid)

		buf = buf[SizeFullIdentity:]
	}

	return nil
}

type DiscoveryResponseHeader struct {
	SendIDAddr    identity.IdentityAddress
	Flags         flags.Flags
	IdentityCount uint8
}

func (discresphdr *DiscoveryResponseHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := discresphdr.SendIDAddr.CheckSize(); err != nil {
		return nil, err
	}

	// Encode SendIDAddr
	b = append(b, discresphdr.SendIDAddr...)

	// Encode Flags
	b = append(b, byte(discresphdr.Flags))

	// Encode IdentityCount
	b = append(b, byte(discresphdr.IdentityCount))

	return b, nil
}

func (discresphdr *DiscoveryResponseHeader) MarshalBinary() ([]byte, error) {
	b, err := discresphdr.AppendBinary(make([]byte, 0, SizeDiscoveryResponseHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (discresphdr *DiscoveryResponseHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeDiscoveryResponseHeader {
		return &errs.SizeError{
			SubjectName:         "DiscoveryResponseHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeDiscoveryResponseHeader,
		}
	}

	// Decode SendIDAddr
	discresphdr.SendIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(discresphdr.SendIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode Flags
	discresphdr.Flags = flags.Flags(buf[0])

	buf = buf[SizeFlags:]

	// Decode IdentityCount
	discresphdr.IdentityCount = uint8(buf[0])

	return nil
}

type DiscoveryResponse struct {
	Header     *DiscoveryResponseHeader
	Identities []*FullIdentity
}

func (discresp *DiscoveryResponse) AppendBinary(b []byte) ([]byte, error) {
	if discresp.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	if len(discresp.Identities) != int(discresp.Header.IdentityCount) {
		return nil, &errs.SizeError{
			SubjectName:         "Identities",
			SubjectActualSize:   len(discresp.Identities),
			SubjectExpectedSize: int(discresp.Header.IdentityCount),
		}
	}

	// Encode Header
	b, err := discresp.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Identities
	for idx, fullid := range discresp.Identities {
		if fullid == nil {
			return nil, &errs.IsNilError{SubjectName: fmt.Sprintf("Identities[%d]", idx)}
		}
		b, err = fullid.AppendBinary(b)
		if err != nil {
			return nil, err
		}
	}

	return b, nil
}

func (discresp *DiscoveryResponse) MarshalBinary() ([]byte, error) {
	if discresp.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	sizeDiscoveryResponse := SizeDiscoveryResponseHeader + (int(discresp.Header.IdentityCount) * SizeFullIdentity)
	b, err := discresp.AppendBinary(make([]byte, 0, sizeDiscoveryResponse))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (discresp *DiscoveryResponse) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < SizeDiscoveryResponseHeader {
		return &errs.MinSizeError{
			SubjectName:         "DiscoveryResponse",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeDiscoveryResponseHeader,
		}
	}

	// Decode Header
	discresphdrByte := make([]byte, SizeDiscoveryResponseHeader)
	copy(discresphdrByte, buf[:SizeDiscoveryResponseHeader])
	discresphdr := &DiscoveryResponseHeader{}
	if err := discresphdr.UnmarshalBinary(discresphdrByte); err != nil {
		return err
	}
	discresp.Header = discresphdr

	buf = buf[SizeDiscoveryResponseHeader:]

	sizeIdentities := int(discresphdr.IdentityCount) * SizeFullIdentity
	if len(buf) != sizeIdentities {
		return &errs.SizeError{
			SubjectName:         "Identities",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: sizeIdentities,
		}
	}

	// Decode Identities
	discresp.Identities = make([]*FullIdentity, 0, discresphdr.IdentityCount)
	for range discresphdr.IdentityCount {
		fullidByte := make([]byte, SizeFullIdentity)
		copy(fullidByte, buf[:SizeFullIdentity])
		fullid := &FullIdentity{}
		if err := fullid.UnmarshalBinary(fullidByte); err != nil {
			return err
		}
		discresp.Identities = append(discresp.Identities, fullid)

		buf = buf[SizeFullIdentity:]
	}

	return nil
}
