package main

import (
	"fmt"

	"github.com/ickerwx/cryptopals/common"
)

func main() {
	text := []byte("ICE ICE BABY")

	// this will work
	b := append(text, []byte{4, 4, 4, 4}...)
	result, err := common.StripPkcs7Padding(b)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(result))
	}

	// this will throw an error
	b = append(text, []byte{5, 5, 5, 5}...)
	result, err = common.StripPkcs7Padding(b)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(result))
	}

	// this will also throw an error
	b = append(text, []byte{1, 2, 3, 4}...)
	result, err = common.StripPkcs7Padding(b)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(result))
	}
}
