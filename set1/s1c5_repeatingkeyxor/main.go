package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	ciphertext := common.Xor([]byte(plaintext), []byte(key))
	cipherhex := hex.EncodeToString(ciphertext)

	if cipherhex == expected {
		fmt.Println("Encrypted data matches expected data:")
	} else {
		fmt.Println("Encrypted data does NOT match expected data!")
	}
	fmt.Println(cipherhex)

}
