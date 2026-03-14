package ipcprotocol

import (
	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeContactCount              = 2
	SizeListContactsResponseHeader = SizeContactCount
)

type ListContactsResponseHeader struct {
	ContactCount uint16
}

func (hdr *ListContactsResponseHeader) AppendBinary(b []byte) ([]byte, error) {
	b = common.Uint16AppendBinary(b, hdr.ContactCount)
	return b, nil
}

func (hdr *ListContactsResponseHeader) MarshalBinary() ([]byte, error) {
	return hdr.AppendBinary(make([]byte, 0, SizeListContactsResponseHeader))
}

func (hdr *ListContactsResponseHeader) UnmarshalBinary(b []byte) error {
	if len(b) != SizeListContactsResponseHeader {
		return &errs.SizeError{
			SubjectName:         "ListContactsResponseHeader",
			SubjectActualSize:   len(b),
			SubjectExpectedSize: SizeListContactsResponseHeader,
		}
	}
	hdr.ContactCount = common.Uint16UnmarshalBinary(b[:SizeContactCount])
	return nil
}

type ListContactsResponse struct {
	Header    *ListContactsResponseHeader
	Addresses []identity.IdentityAddress
}

func (resp *ListContactsResponse) AppendBinary(b []byte) ([]byte, error) {
	if resp.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	b, err := resp.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}
	for _, addr := range resp.Addresses {
		if err := addr.CheckSize(); err != nil {
			return nil, err
		}
		b = append(b, addr...)
	}
	return b, nil
}

func (resp *ListContactsResponse) MarshalBinary() ([]byte, error) {
	return resp.AppendBinary(nil)
}

func (resp *ListContactsResponse) UnmarshalBinary(b []byte) error {
	if len(b) < SizeListContactsResponseHeader {
		return &errs.MinSizeError{
			SubjectName:         "ListContactsResponse",
			SubjectActualSize:   len(b),
			SubjectExpectedSize: SizeListContactsResponseHeader,
		}
	}

	hdr := &ListContactsResponseHeader{}
	if err := hdr.UnmarshalBinary(b[:SizeListContactsResponseHeader]); err != nil {
		return err
	}
	resp.Header = hdr

	buf := b[SizeListContactsResponseHeader:]
	resp.Addresses = make([]identity.IdentityAddress, 0, hdr.ContactCount)
	for range hdr.ContactCount {
		if len(buf) < identity.SizeIdentityAddress {
			return &errs.MinSizeError{
				SubjectName:         "IdentityAddress",
				SubjectActualSize:   len(buf),
				SubjectExpectedSize: identity.SizeIdentityAddress,
			}
		}
		addr := make(identity.IdentityAddress, identity.SizeIdentityAddress)
		copy(addr, buf[:identity.SizeIdentityAddress])
		resp.Addresses = append(resp.Addresses, addr)
		buf = buf[identity.SizeIdentityAddress:]
	}

	return nil
}
