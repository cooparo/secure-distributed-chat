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
	Flags uint8
	AdditionalLength uint8
	DataLength uint16
	PrevChainCount uint8
	ChainCount uint8
}
