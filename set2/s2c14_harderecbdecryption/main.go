package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"

	"github.com/ickerwx/cryptopals/common"
)

var key, randomPrefix []byte

func blackBox(plaintext []byte) []byte {
	// the blackbox will encrypt anything we throw at it after appending the secret we are interested in and after prepending a random prefix
	secretb64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secret, _ := base64.StdEncoding.DecodeString(secretb64)
	plaintext = append(randomPrefix, plaintext...)
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

func createDictionary(prefix, buffer []byte, firstUserBlock int) map[[16]byte]byte {
	dictionary := make(map[[16]byte]byte)
	var temp [16]byte
	// buffer is supposed to always be 15 bytes long

	for i := 0; i < 256; i++ {
		foo := append(buffer, byte(i))
		ciphertext := blackBox(append(prefix, foo...))
		copy(temp[:], ciphertext[firstUserBlock*16:(firstUserBlock+1)*16])
		dictionary[temp] = foo[15]
	}

	return dictionary
}

func dictLookup(key []byte, dictionary map[[16]byte]byte, blockNum int) byte {
	var temp [16]byte
	copy(temp[:], key[blockNum*16:(blockNum+1)*16])
	return dictionary[temp]
}

// detectPrefixInfo will try to find out how many bytes we need to prepend to get a known block alignment, and it will try to
// find the first block that contains user data
func detectPrefixInfo() (int, int) {
	//this is simply a block of 32 A's
	// we will brute force a prefix length until we get two repeating blocks
	blockOfAs := []byte{65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65}

	for len := 0; len < 16; len++ {
		prefix := make([]byte, len)
		for i := range prefix {
			prefix[i] = 'A'
		}
		ciphertext := blackBox(append(prefix, blockOfAs...))
		chunks, _ := common.Chunks(ciphertext, 16)
		if common.HasDuplicateBlocks(chunks) {
			// if we have two duplicate blocks, then we know how much data we need to prepend for block alignment
			// now we need to know which is the first block that has our data, so basically the index of the first repeating chunk
			for blockNum := range chunks {
				var left, right [16]byte
				copy(left[:], chunks[blockNum][:16])
				copy(right[:], chunks[blockNum+1][:16])
				if left == right {
					return len, blockNum
				}
			}
		}
	}
	return -1, -1
}

func main() {
	rand.Seed(time.Now().UnixNano())
	randomCount := rand.Intn(255) + 1
	randomPrefix = common.RandomBytes(randomCount)
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
		prefixPadCount, firstUserBlock := detectPrefixInfo() // find out how many bytes we have to prepend to get our target block alignment
		prefix := make([]byte, prefixPadCount)
		for i := range prefix {
			prefix[i] = 'A'
		}
		// if we are here, we have duplicate blocks, so we assume the black box is using ECB
		var plaintext []byte // will hold the recovered plaintext bytes
		for blockNum := 0; blockNum < numOfBlocks-firstUserBlock; blockNum++ {
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
				- we also need a slice called prefix to align our block due to the unknown random data at the start
				- we track the start of our data in firstUserBlock
			*/
			for bufferByte := 0; bufferByte < 16; bufferByte++ {
				buffer := make([]byte, 15-bufferByte)
				for i := 0; i < len(buffer)-bufferByte; i++ {
					buffer[i] = 'A'
				}
				ciphertext := blackBox(append(prefix, buffer...))
				var dictionary map[[16]byte]byte
				if blockNum == 0 {
					dictionary = createDictionary(prefix, append(buffer, plaintext...), firstUserBlock)
				} else {
					dictionary = createDictionary(prefix, plaintext[len(plaintext)-15:], firstUserBlock)
				}
				char := dictLookup(ciphertext, dictionary, firstUserBlock+blockNum)
				plaintext = append(plaintext, char)
			}
		}
		fmt.Println(string(plaintext))
	}
}
