package doubleratchet

import "fmt"

// Uninitialized Chain Error
type UninitializedChainError struct {
	ChainName string
}

func (e *UninitializedChainError) Error() string {
	return fmt.Sprintf("%s chain is not initialized", e.ChainName)
}
