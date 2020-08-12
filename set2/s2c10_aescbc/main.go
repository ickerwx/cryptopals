package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	data, _ := ioutil.ReadFile("./data")
	ciphertext, _ := base64.StdEncoding.DecodeString(string(data))
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	plaintext, _ := common.AesCbcDecrypt(append(iv, ciphertext...), key)
	fmt.Println(string(plaintext))

	ciphertext2, _ := common.AesCbcEncrypt(plaintext, key, iv)

	fmt.Println("My encrypted data matches given data:", bytes.Equal(ciphertext, ciphertext2))

	s := []byte("This is a nice little test")
	p := common.Pkcs7Padding(s, 16)
	c, _ := common.AesCbcEncrypt(p, key, iv)
	p2, _ := common.AesCbcDecrypt(c, key)
	s2, _ := common.StripPkcs7Padding(p2)

	fmt.Printf("Equal plaintexts: %t, equal padded text: %t\n", bytes.Equal(s, s2), bytes.Equal(p, p2))
	fmt.Printf("%s == %s\n", string(s), string(s2))

}
