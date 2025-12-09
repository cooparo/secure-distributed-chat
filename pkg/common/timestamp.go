package common

const SizeTimestamp = 8

type Timestamp int64

func (t *Timestamp) AppendBinary(b []byte) ([]byte, error) {
	ts := *t

	return append(b,
		byte(ts>>56),
		byte(ts>>48),
		byte(ts>>40),
		byte(ts>>32),
		byte(ts>>24),
		byte(ts>>16),
		byte(ts>>8),
		byte(ts)), nil
}

func (t *Timestamp) MarshalBinary() ([]byte, error) {
	b, err := t.AppendBinary(make([]byte, 0, SizeTimestamp))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (t *Timestamp) UnmarshalBinary(b []byte) error {
	ts := int64(b[7]) |
		int64(b[6])<<8 |
		int64(b[5])<<16 |
		int64(b[4])<<24 |
		int64(b[3])<<32 |
		int64(b[2])<<40 |
		int64(b[1])<<48 |
		int64(b[0])<<56

	*t = Timestamp(ts)
	return nil
}
