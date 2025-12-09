package flags

type Flags uint8

func Set(a, b Flags) Flags {
	return a | b
}

func Clear(a, b Flags) Flags {
	return a &^ b
}

func Toggle(a, b Flags) Flags {
	return a ^ b
}

func Has(a, b Flags) bool {
	return a&b != 0
}

func HasAll(a, b Flags) bool {
	return a&b == b
}
