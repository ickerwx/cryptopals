package main

import (
	"encoding/base64"
	"fmt"

	"github.com/ickerwx/cryptopals/common"
)

var key []byte

func blackBox(plaintext []byte) []byte {
	// the blackbox will encrypt anything we throw at it after appending the secret we are interested in
	secretb64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secret, _ := base64.StdEncoding.DecodeString(secretb64)
	plaintext = append(plaintext, secret...)
	plaintext = common.Pkcs7Padding(plaintext, 16)
	ciphertext, _ := common.AesEcbEncrypt(plaintext, key)
	return ciphertext
}

func detectBlocksize() int {
	// get the initial length, then send bytes until the ciphertext length changes. The difference is the cipher's block length.
	initialLength := len(blackBox([]byte("")))
	for i := 1; i < 256; i++ {
		temp := make([]byte, i)
		length := len(blackBox(temp))
		if length != initialLength {
			return length - initialLength
		}
	}
	return 0
}

func createDictionary(buffer []byte) map[[16]byte]byte {
	dictionary := make(map[[16]byte]byte)
	var temp [16]byte
	// buffer is supposed to always be 15 bytes long

	for i := 0; i < 256; i++ {
		foo := append(buffer, byte(i))
		ciphertext := blackBox(foo)
		copy(temp[:], ciphertext[0:16])
		dictionary[temp] = foo[15]
	}

	return dictionary
}

func dictLookup(key []byte, dictionary map[[16]byte]byte, blockNum int) byte {
	var temp [16]byte
	copy(temp[:], key[blockNum*16:(blockNum+1)*16])
	return dictionary[temp]
}

func main() {
	key = common.RandomBytes(16)

	// first we detect the blocksize
	blocksize := detectBlocksize()
	testbuffer := make([]byte, 3*blocksize)
	for i := range testbuffer {
		testbuffer[i] = 'A'
	}
	numOfBlocks := len(blackBox([]byte(""))) / 16 // we need to know how many blocks the secret message generates w/o our data

	// now we send enough A's to make sure we get two repeating blocks
	temp := blackBox(testbuffer)
	chunks, _ := common.Chunks(temp, blocksize) // split the ciphertext into chunks to check for duplicate blocks
	if common.HasDuplicateBlocks(chunks) {
		// if we are here, we have duplicate blocks, so we assume the black box is using ECB
		var plaintext []byte // will hold the recovered plaintext bytes
		for blockNum := 0; blockNum < numOfBlocks; blockNum++ {
			// now we start to recover each block
			/*
				What we do is:
				- build a sliding buffer that starts at length 15 and ends at length 0 (buffer)
				- because the length is 15, one byte of the secret message will be in the first block
				- use the blackbox to request all 256 different ciphertext blocks, then compare the actual block with the dictionary to recover the first byte
				- now reduce buffer length by 1. Two bytes of secret will leak into the first block, of which we already know the first one. Request 256 ciphertexts, compare.
				- rinse, repeat
				- once the first block is completely recovered, we will use the buffer to ensure that the first byte of the second secret block leaks into the first secret block,
				- since we have recovered the first block of plaintext, we will from now on build the dictionary from the last 15 bytes of plaintext and slide through all the remaining blocks
			*/
			for bufferByte := 0; bufferByte < 16; bufferByte++ {
				buffer := make([]byte, 15-bufferByte)
				for i := 0; i < len(buffer)-bufferByte; i++ {
					buffer[i] = 'A'
				}
				ciphertext := blackBox(buffer)
				var dictionary map[[16]byte]byte
				if blockNum == 0 {
					dictionary = createDictionary(append(buffer, plaintext...))
				} else {
					dictionary = createDictionary(plaintext[len(plaintext)-15:])
				}
				char := dictLookup(ciphertext, dictionary, blockNum)
				plaintext = append(plaintext, char)
			}
		}
		fmt.Println(string(plaintext))
	}
}
