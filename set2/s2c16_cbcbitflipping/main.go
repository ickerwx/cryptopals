package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ickerwx/cryptopals/common"
)

var key []byte

func blackbox(userdata string) []byte {
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	userdata = strings.ReplaceAll(userdata, ";", "_")
	userdata = strings.ReplaceAll(userdata, "=", "_")

	data := append(prefix, []byte(userdata)...)
	data = append(data, suffix...)
	data = common.Pkcs7Padding(data, 16)
	ciphertext, err := common.AesCbcEncrypt(data, key, common.RandomBytes(16))
	if err != nil {
		panic(err)
	}
	return ciphertext
}

func checkAdmin(ciphertext []byte) bool {
	plaintext, err := common.AesCbcDecrypt(ciphertext, key)
	if err != nil {
		panic(err)
	}
	plaintext, err = common.StripPkcs7Padding(plaintext)
	if err != nil {
		panic(err)
	}
	v, err := url.ParseQuery(string(plaintext))
	if err != nil {
		panic(err)
	}
	for key := range v {
		if key == "admin" {
			if v.Get("admin") == "true" {
				return true
			}
		}
	}
	return false
}

func main() {
	/*
		0 iviviviviviviviv
		1 comment1=cooking
		2 %20MCs;userdata=
		3 AAAAAAAAAAAAAAAA
		4 ;admin=true;AAAA
		5 ;comment2=%20lik
		6 e%20a%20pound%20
		7 of%20bacon
	*/
	key = common.RandomBytes(16)
	ciphertext := blackbox("AAAAAAAAAAAAAAAA;admin=true;AAAA")
	fmt.Println("Checking admin privs before bitflipping:")
	isAdmin := checkAdmin(ciphertext)
	fmt.Printf("isAdmin=%t\n\n", isAdmin)
	fmt.Println("Flipping bits")
	blocks, _ := common.Chunks(ciphertext, 16)
	// b ^ c1 = _  -> _ ^ c1 = b
	// b ^ c2 = ;  -> b ^ ; = c2
	// replace c1 with c2 in block number 3 at position 0 and 11, same for = at position 6
	c1 := blocks[3][0]
	b := '_' ^ c1
	c2 := b ^ ';'
	blocks[3][0] = c2

	c1 = blocks[3][6]
	b = '_' ^ c1
	c2 = b ^ '='
	blocks[3][6] = c2

	c1 = blocks[3][11]
	b = '_' ^ c1
	c2 = b ^ ';'
	blocks[3][11] = c2

	ciphertext = []byte{}

	for i := range blocks {
		ciphertext = append(ciphertext, blocks[i]...)
	}

	isAdmin = checkAdmin(ciphertext)
	fmt.Printf("isAdmin=%t\n", isAdmin)
}
