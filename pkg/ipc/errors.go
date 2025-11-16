package ipc

type IpcError string

const (
	IpcErrorMsgPacket     IpcError = "ipc error [message packet]"
	IpcErrorMsgRespPacket IpcError = "ipc error [message response packet]"
)
