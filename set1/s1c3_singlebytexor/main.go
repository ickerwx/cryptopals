package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	cipherhex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	ciphertext, _ := hex.DecodeString(cipherhex)
	plaintext, _ := common.BreakSingleByteXor(ciphertext)

	fmt.Println(string(plaintext))
}
