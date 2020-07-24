package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	handle, _ := os.Open("./data")
	defer handle.Close()

	scanner := bufio.NewScanner(handle)
	var ciphertexts [][]byte
	for scanner.Scan() {
		c, _ := hex.DecodeString(scanner.Text())
		ciphertexts = append(ciphertexts, c)
	}
	for cI:= range ciphertexts {
		found := false
		chunks, err := common.Chunks(ciphertexts[cI], 16)
		if err != nil {
			panic(err)
		}
		for chI := range chunks {
			if found {
				continue
			}
			for k :=chI + 1; k < len(chunks); k++ {
				if found {
					continue
				}
				if bytes.Equal(chunks[chI], chunks[k]) {
					fmt.Printf("ECB found at ciphertexts[%d]\n", cI)
					fmt.Println(hex.EncodeToString(ciphertexts[cI]))
					found = true
				}
			}
		}
	}
}