package main

import (
	"bytes"
	"fmt"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	fmt.Println(common.Pkcs7Padding([]byte(""), 16))
	fmt.Printf("%q\n", string(common.Pkcs7Padding([]byte(""), 16)))

	fmt.Println(common.Pkcs7Padding([]byte("AAAA"), 16))
	fmt.Printf("%q\n", string(common.Pkcs7Padding([]byte("AAAA"), 16)))

	fmt.Println(common.Pkcs7Padding([]byte("AAAAAAAA"), 16))
	fmt.Printf("%q\n", string(common.Pkcs7Padding([]byte("AAAAAAAA"), 16)))

	fmt.Println(common.Pkcs7Padding([]byte("AAAAAAAAAAAAAAAA"), 16))
	fmt.Printf("%q\n", string(common.Pkcs7Padding([]byte("AAAAAAAAAAAAAAAA"), 16)))

	fmt.Println(common.Pkcs7Padding([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 16))
	fmt.Printf("%q\n", string(common.Pkcs7Padding([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 16)))

	fmt.Println(common.Pkcs7Padding([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 36))
	fmt.Printf("%q\n", string(common.Pkcs7Padding([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 36)))

	s := []byte("AAAAA")
	p := common.Pkcs7Padding(s, 16)
	u, err := common.StripPkcs7Padding(p)
	if err != nil {
		panic(err)
	}
	fmt.Println(bytes.Equal(s, u), common.DetectPkcs7Padding(p))
}
