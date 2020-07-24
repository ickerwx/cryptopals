package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/ickerwx/cryptopals/common"
)

func main() {

	filename := "./data"
	data, _ := ioutil.ReadFile(filename)
	ciphertext, _ := base64.StdEncoding.DecodeString(string(data))

	var keysize int
	minDistance := 100.0
	// try possible key lengths, calculate the Hamming distance for each
	// the key length that results in the shortest distance is probably the correct one
	for k := range [40]int{} {
		k++
		avgDistance := 0.0
		distance := 0
		// take ten samples, average the distance
		for x := range [10]int{} {
			distance += common.HammingDistance(ciphertext[x*k:(x+1)*k], ciphertext[(x+1)*k:(x+2)*k])
		}
		avgDistance = (float64(distance) / 10.0) / float64(k)
		if avgDistance < minDistance {
			minDistance = avgDistance
			keysize = k
		}
	}
	fmt.Println("Keysize is probably", keysize)
	var transposed [][]byte
	i := 0
	// create a slice of byte slices with keysize elements
	for i < keysize {
		transposed = append(transposed, []byte{})
		i++
	}
	// transpose the ciphertext
	for i = range ciphertext {
		transposed[i%keysize] = append(transposed[i%keysize], ciphertext[i])
	}

	var key []byte

	for i = range transposed {
		_, k := common.BreakSingleByteXor(transposed[i])
		key = append(key, k)
	}
	fmt.Printf("Key is probably %s\n%v\n\n", string(key), key)
	fmt.Println(string(common.Xor(ciphertext, key)))

}
