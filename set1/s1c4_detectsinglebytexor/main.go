package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	file, err := os.Open("ciphertexts")
	if err != nil {
		log.Fatal((err))
	}
	defer file.Close()

	ciphertexts := []string{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ciphertexts = append(ciphertexts, scanner.Text())
	}

	lowestChi2 := 20000.0
	var finalPlaintext []byte

	for _, ciphertext := range ciphertexts {
		// for every ciphertext, brute-force the key and get the chi2 value
		// the overall lowest chi2 over all possible plaintexts is what we are looking for
		var plaintext []byte
		cipherbytes, _ := hex.DecodeString(ciphertext)
		minChi2 := 20000.0

		for i := range [255]byte{} { // brute-force the key byte
			k := make([]byte, 1)
			k[0] = byte(i)
			plain := common.Xor(cipherbytes, k)
			chisquared := common.ChiSquared(plain)

			if chisquared < minChi2 {
				// if we found a new lowest chi2, replace the existing
				//plaintext with the new one
				minChi2 = chisquared
				plaintext = plain
			}
		}

		if minChi2 < lowestChi2 {
			lowestChi2 = minChi2
			finalPlaintext = plaintext
		}
	}
	fmt.Println(strings.TrimSuffix(string(finalPlaintext), "\n"))
}
