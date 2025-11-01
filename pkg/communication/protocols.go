package communication

type PacketType uint8

const (
	PacketTypeMessage PacketType = iota
)

var packetTypeName = map[PacketType]string{
	PacketTypeMessage: "message",
}


type mainHeader struct {
	Version    uint8
	PacketType PacketType
}

type messageHeader struct {
	Length uint16
}
