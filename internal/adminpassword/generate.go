package adminpassword

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Character classes, in Windows LAPS' complexity order. Symbols avoid
// quotes, backslash and space, which break copy-paste and shells.
var classes = [4]string{
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"abcdefghijklmnopqrstuvwxyz",
	"0123456789",
	"!#$%&()*+,-./:;<=>?@[]^_{|}~",
}

// Generate returns a password of length characters with at least one from
// every class complexity enables (1–4), drawn from crypto/rand. The caller
// zeroes the returned slice when done.
func Generate(length, complexity int) ([]byte, error) {
	if complexity < 1 || complexity > len(classes) {
		return nil, fmt.Errorf("complexity %d is not 1–4", complexity)
	}
	if length < complexity || length > MaxLength {
		return nil, fmt.Errorf("length %d is out of range", length)
	}
	alphabet := ""
	for _, c := range classes[:complexity] {
		alphabet += c
	}
	pw := make([]byte, length)
	// One character from each class first, then the rest from the whole
	// alphabet, then a shuffle so the required ones aren't at the front.
	for i := 0; i < complexity; i++ {
		c, err := pick(classes[i])
		if err != nil {
			return nil, err
		}
		pw[i] = c
	}
	for i := complexity; i < length; i++ {
		c, err := pick(alphabet)
		if err != nil {
			return nil, err
		}
		pw[i] = c
	}
	for i := length - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return nil, err
		}
		pw[i], pw[j] = pw[j], pw[i]
	}
	return pw, nil
}

func pick(set string) (byte, error) {
	i, err := randInt(len(set))
	if err != nil {
		return 0, err
	}
	return set[i], nil
}

// randInt returns a uniform index in [0, n) without modulo bias. It stays
// int64 (Go indexes with any integer type), so nothing is narrowed.
func randInt(n int) (int64, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("read random: %w", err)
	}
	return v.Int64(), nil
}

// zero overwrites b.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
