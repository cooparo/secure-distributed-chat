package ipcprotocol

type MessageData []byte

func (msgdata *MessageData) AppendBinary(b []byte) []byte {
	return append(b, *msgdata...)
}

func (msgdata *MessageData) MarshalBinary(datalen uint16) ([]byte, error) {
	b := make([]byte, 0, datalen)

	b = msgdata.AppendBinary(b)

	return b, nil
}

//func (msgreqhdr *MessageData) UnmarshalBinary(b []byte, datalen int) error {
//	buf := b
//
//	if len(buf) != datalen {
//		return &errs.SizeError{
//			SubjectName:         "MessageData",
//			SubjectActualSize:   len(buf),
//			SubjectExpectedSize: datalen,
//		}
//	}
//	msgreqhdr.Address = make([]byte, identity.SizeIdentityAddress)
//	copy(msgreqhdr.Address, buf[:identity.SizeIdentityAddress])
//
//	return nil
//}
