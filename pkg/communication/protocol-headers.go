package communication

type mainHeader struct {
	Version    uint8
	PacketType uint8
}

type messageHeader struct {
	Length uint16
}
