package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func main() {
	// should convert 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d to SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
	h := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	decoded, _ := hex.DecodeString(h)
	b64 := base64.StdEncoding.EncodeToString(decoded)
	fmt.Println(b64)
}
