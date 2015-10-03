package algorithms

var (
	registry = make(map[string]func() Algorithm)
)

// Algorithm implementations encrypt and decrypt data.
type Algorithm interface {
	Encrypt(key *[32]byte, data []byte) ([]byte, error)
	Decrypt(key *[32]byte, ciphertext []byte) ([]byte, error)
	Label() string
	NeedsKey() bool
}

// New returns an Algorithm corresponding to the requested cipher.
func New(algorithm string) Algorithm {
	if constructor, present := registry[algorithm]; present {
		return constructor()
	}
	return nil
}

// GetDefaultAlgorithm returns the default algorithm.
func GetDefaultAlgorithm() string {
	return secretBoxLabel
}

// GetAlgorithms returns a list of registered algorithms.
func GetAlgorithms() []string {
	var algos []string
	for k := range registry {
		algos = append(algos, k)
	}
	return algos
}
