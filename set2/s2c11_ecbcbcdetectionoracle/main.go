package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ickerwx/cryptopals/common"
)

var aesCBC = 0
var aesECB = 1

func encryptionOracle(plaintext []byte) []byte {
	// first we create a byte slice that is between 5 and 10 bytes long and contains random data
	rand.Seed(time.Now().UnixNano())
	randomLength := rand.Intn(6) + 5
	randomBuffer := common.RandomBytes(randomLength)

	// use the random data to prefix and suffix the plaintext
	plaintext = append(randomBuffer, plaintext...)
	plaintext = append(plaintext, randomBuffer...)
	plaintext = common.Pkcs7Padding(plaintext, 16)

	key := common.RandomBytes(16)

	choice := rand.Int() % 2
	var ciphertext []byte
	if choice == aesCBC {
		// we will do AES CBC
		iv := common.RandomBytes(16)
		ciphertext, _ = common.AesCbcEncrypt(plaintext, key, iv)
	} else {
		// we will do AES ECB
		ciphertext, _ = common.AesEcbEncrypt(plaintext, key)
	}
	if choice == aesCBC {
		fmt.Println("AES CBC used by Oracle")
	} else {
		fmt.Println("AES ECB used by Oracle")
	}
	return ciphertext
}

func main() {
	for i := 0; i < 20; i++ {
		ciphertext := encryptionOracle([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
		chunks, _ := common.Chunks(ciphertext, 16)
		if common.HasDuplicateBlocks(chunks) {
			fmt.Printf("AES ECB detected\n\n")
		} else {
			fmt.Printf("AES CBC detected\n\n")
		}
	}
}
