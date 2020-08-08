package main

import (
	"fmt"
	"net/url"

	"github.com/ickerwx/cryptopals/common"
)

var key []byte

func profileFor(profile string) []byte {
	s := "email=" + profile + "&uid=10&role=user"
	plaintext := common.Pkcs7Padding([]byte(s), 16)
	ciphertext, _ := common.AesEcbEncrypt(plaintext, key)
	fmt.Println("Encrypting profile with role=user")
	return ciphertext
}

func getUserRole(ciphertext []byte) string {
	plaintext, _ := common.AesEcbDecrypt(ciphertext, key)
	plaintext, _ = common.StripPkcs7Padding(plaintext)
	v, _ := url.ParseQuery(string(plaintext))
	return v.Get("role")
}

func main() {
	key = common.RandomBytes(16)
	profile := []byte("AAAAAAAAAAadmin")
	profile = append(profile, []byte{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 65, 65, 65}...) // this is padding for the second block plus stray A's for alignment
	ciphertext := profileFor(string(profile))
	/*
		ciphertext will have four blocks that now look like this:
			email=AAAAAAAAAA
			adminbbbbbbbbbbb  <- b means 0xb
			AAA&uid=10&role=
			user<padding>

			The second block, starting with admin, happens to be correctly padded. We take this block
			and replace the last block with this one, thereby replacing user<padding> with admin<padding>

			Our email field is garbage, but the role is now admin.
	*/
	adminBlock := ciphertext[16:32]
	role := getUserRole(append(ciphertext[:48], adminBlock...))
	fmt.Println("The profile's role is", role)
}
