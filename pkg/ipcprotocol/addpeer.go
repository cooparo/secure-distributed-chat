package ipcprotocol

import (
	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
)

const (
	SizeAddressLength    = 2
	SizeAddPeerHeader    = SizeAddressLength
)

type AddPeerHeader struct {
	AddressLength uint16
}

func (hdr *AddPeerHeader) AppendBinary(b []byte) ([]byte, error) {
	b = common.Uint16AppendBinary(b, hdr.AddressLength)
	return b, nil
}

func (hdr *AddPeerHeader) MarshalBinary() ([]byte, error) {
	return hdr.AppendBinary(make([]byte, 0, SizeAddPeerHeader))
}

func (hdr *AddPeerHeader) UnmarshalBinary(b []byte) error {
	if len(b) != SizeAddPeerHeader {
		return &errs.SizeError{
			SubjectName:         "AddPeerHeader",
			SubjectActualSize:   len(b),
			SubjectExpectedSize: SizeAddPeerHeader,
		}
	}
	hdr.AddressLength = common.Uint16UnmarshalBinary(b[:SizeAddressLength])
	return nil
}

type AddPeer struct {
	Header *AddPeerHeader
	Data   []byte // network address string (e.g. "node2" or "172.18.0.3")
}

func (ap *AddPeer) AppendBinary(b []byte) ([]byte, error) {
	if ap.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	b, err := ap.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}
	b = append(b, ap.Data...)
	return b, nil
}

func (ap *AddPeer) MarshalBinary() ([]byte, error) {
	return ap.AppendBinary(nil)
}
