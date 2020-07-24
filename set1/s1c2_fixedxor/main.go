package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	plaintextStr := "1c0111001f010100061a024b53535009181c"
	keyStr := "686974207468652062756c6c277320657965"
	expectedStr := "746865206b696420646f6e277420706c6179"

	plaintextBytes, _ := hex.DecodeString(plaintextStr)
	keyBytes, _ := hex.DecodeString(keyStr)

	ciphertextBytes := common.Xor(plaintextBytes, keyBytes)
	ciphertextStr := hex.EncodeToString(ciphertextBytes)

	fmt.Println(" expected:", expectedStr)
	fmt.Println("      got:", ciphertextStr)
	fmt.Println("decrypted:", string(ciphertextBytes))
}
