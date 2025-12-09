package common

// Uint8

func Uint8AppendBinary(b []byte, v uint8) []byte {
	return append(b, byte(v))
}

func Uint8MarshalBinary(v uint8) []byte {
	return Uint8AppendBinary(make([]byte, 0, 1), v)
}

func Uint8UnmarshalBinary(b []byte) uint8 {
	return uint8(b[0])
}

// Int8

func Int8AppendBinary(b []byte, v int8) []byte {
	return append(b, byte(v))
}

func Int8MarshalBinary(v int8) []byte {
	return Int8AppendBinary(make([]byte, 0, 1), v)
}

func Int8UnmarshalBinary(b []byte) int8 {
	return int8(b[0])
}

// Uint16

func Uint16AppendBinary(b []byte, v uint16) []byte {
	return append(b,
		byte(v>>8),
		byte(v))
}

func Uint16MarshalBinary(v uint16) []byte {
	return Uint16AppendBinary(make([]byte, 0, 2), v)
}

func Uint16UnmarshalBinary(b []byte) uint16 {
	return uint16(b[1]) |
		uint16(b[0])<<8
}

// Int16

func Int16AppendBinary(b []byte, v int16) []byte {
	return append(b,
		byte(v>>8),
		byte(v))
}

func Int16MarshalBinary(v int16) []byte {
	return Int16AppendBinary(make([]byte, 0, 2), v)
}

func Int16UnmarshalBinary(b []byte) int16 {
	return int16(b[1]) |
		int16(b[0])<<8
}

// Uint32

func Uint32AppendBinary(b []byte, v uint32) []byte {
	return append(b,
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v))
}

func Uint32MarshalBinary(v uint32) []byte {
	return Uint32AppendBinary(make([]byte, 0, 4), v)
}

func Uint32UnmarshalBinary(b []byte) uint32 {
	return uint32(b[3]) |
		uint32(b[2])<<8 |
		uint32(b[1])<<16 |
		uint32(b[0])<<24
}

// Int32

func Int32AppendBinary(b []byte, v int32) []byte {
	return append(b,
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v))
}

func Int32MarshalBinary(v int32) []byte {
	return Int32AppendBinary(make([]byte, 0, 4), v)
}

func Int32UnmarshalBinary(b []byte) int32 {
	return int32(b[3]) |
		int32(b[2])<<8 |
		int32(b[1])<<16 |
		int32(b[0])<<24
}

// Uint64

func Uint64AppendBinary(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v))
}

func Uint64MarshalBinary(v uint64) []byte {
	return Uint64AppendBinary(make([]byte, 0, 8), v)
}

func Uint64UnmarshalBinary(b []byte) uint64 {
	return uint64(b[7]) |
		uint64(b[6])<<8 |
		uint64(b[5])<<16 |
		uint64(b[4])<<24 |
		uint64(b[3])<<32 |
		uint64(b[2])<<40 |
		uint64(b[1])<<48 |
		uint64(b[0])<<56
}

// Int64

func Int64AppendBinary(b []byte, v int64) []byte {
	return append(b,
		byte(v>>56),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v))
}

func Int64MarshalBinary(v int64) []byte {
	return Int64AppendBinary(make([]byte, 0, 1), v)
}

func Int64UnmarshalBinary(b []byte) int64 {
	return int64(b[7]) |
		int64(b[6])<<8 |
		int64(b[5])<<16 |
		int64(b[4])<<24 |
		int64(b[3])<<32 |
		int64(b[2])<<40 |
		int64(b[1])<<48 |
		int64(b[0])<<56
}
