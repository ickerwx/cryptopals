package common

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

var frequency = map[string]float64{
	"a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702,
	"f": 0.02228, "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153,
	"k": 0.00772, "l": 0.04025, "m": 0.02406, "n": 0.06749, "o": 0.07507,
	"p": 0.01929, "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
	"u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150, "y": 0.01974,
	"z": 0.00074, " ": 0.23200}

// ChiSquared will compare plaintext against the English alphabet and return a sum. The lower, the better
func ChiSquared(plaintext []byte) float64 {
	// if plaintext is not at least 80% ascii text. we ignore it
	asciicount := 0.0
	for i := range plaintext {
		if strings.Contains("abcdefghijklmnopqrstuvwxyz ", strings.ToLower(string(plaintext[i]))) {
			asciicount++
		}
	}
	if asciicount < 0.8*float64(len(plaintext)) {
		return 10000.0
	}
	chisquared := 0.0
	plain := strings.ToLower(string(plaintext))
	plainlen := len(plaintext)

	for char := range frequency {
		charcount := float64(strings.Count(plain, char))
		expected := float64(plainlen) * frequency[char]
		chisquared += math.Pow(charcount-expected, 2) / expected
	}
	return chisquared
}

// Xor will xor plain and key
func Xor(plain []byte, key []byte) []byte {
	cipherbytes := make([]byte, len(plain))
	keylen := len(key)

	for i := range plain {
		cipherbytes[i] = plain[i] ^ key[i%keylen]
	}

	return cipherbytes
}

// BreakSingleByteXor takes a byte slice and will brute-force a single byte key. It returns a byte slice
// that most closely looks like English text, as well as the key byte
func BreakSingleByteXor(ciphertext []byte) (plaintext []byte, key byte) {
	minCount := 10000.0

	for i := range [255]byte{} {
		k := make([]byte, 1)
		k[0] = byte(i)
		plain := Xor(ciphertext, k)
		count := ChiSquared(plain)
		if count < minCount {
			minCount = count
			plaintext = plain
			key = k[0]
		}
	}
	return
}

// CountOnes will take an int and return the number of 1's in the binary form of x.
// So for x=2 it will return 1, for x=3 it returns 2, x=7 returns 3 and so on.
func countOnes(x byte) (sum int) {
	sum = 0
	for x > 0 {
		sum = sum + int(x&1)
		x = x >> 1
	}
	return
}

// HammingDistance will calculate the Hamming distance between two []byte.
func HammingDistance(s1, s2 []byte) (distance int) {
	var shorter []byte
	if len(s1) > len(s2) {
		shorter = s2
	} else {
		shorter = s1
	}
	distance = 0
	for i := range shorter {
		distance += countOnes(s1[i] ^ s2[i])
	}
	return
}

// Chunks will take a byte slice and split it into chunks of size length.
func Chunks(slice []byte, length int) ([][]byte, error) {
	if len(slice)%length != 0 {
		err := errors.New("Slice length is not a multiple of " + strconv.Itoa(length))
		return nil, err
	}
	chunks := make([][]byte, len(slice)/length)
	for i := range chunks {
		chunks[i] = slice[i*length : (i+1)*length]
	}
	return chunks, nil
}
