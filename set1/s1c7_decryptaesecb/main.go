package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

func main() {
	filename := "./data"
	data, _ := ioutil.ReadFile(filename)
	ciphertext, _ := base64.StdEncoding.DecodeString(string(data))
	key := []byte("YELLOW SUBMARINE")
	cipher, _ := aes.NewCipher(key)
	buffer := make([]byte, 16)
	var plaintext []byte
	blocks := len(ciphertext) / 16
	for i := 0; i < blocks; i++ {
		cipher.Decrypt(buffer, ciphertext[i*16:(i+1)*16])
		plaintext = append(plaintext, buffer...)
	}
	fmt.Print(string(plaintext))
}
