package main

import (
	"bufio"
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
	for cI := range ciphertexts {
		chunks, err := common.Chunks(ciphertexts[cI], 16)
		if err != nil {
			panic(err)
		}
		if common.HasDuplicateBlocks(chunks) {
			fmt.Printf("Duplicate block detected in ciphertexts[%d]\n", cI)
			for i := range chunks {
				fmt.Println(chunks[i])
			}
		}
	}
}
