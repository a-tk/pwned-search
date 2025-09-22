package main

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"testing"
)

// these need to get a hash, ask the API for a list, and use that list in the bench
// use a password for this that isn't in the result set (and check the result set has
// at least hundreds of entries) Worst case search in both cases

func Benchmark_bodySearchSplit(b *testing.B) {

	//sum := sha1.Sum([]byte("correct horse batt$ery staple"))
	sum := sha1.Sum([]byte("1234"))
	sumString := strings.ToUpper(fmt.Sprintf("%x", sum))

	sha1FirstFive := sumString[:5]
	sha1Last := sumString[5:]

	body, _ := rangeRequest(sha1FirstFive)

	for i := 0; i < b.N; i++ {
		bodySearch(body, sha1Last)
	}
}

func Benchmark_bodySearchKMP(b *testing.B) {

	//sum := sha1.Sum([]byte("correct horse batt$ery staple"))
	sum := sha1.Sum([]byte("1234"))
	sumString := strings.ToUpper(fmt.Sprintf("%x", sum))

	sha1FirstFive := sumString[:5]
	sha1Last := sumString[5:]

	body, _ := rangeRequest(sha1FirstFive)

	for i := 0; i < b.N; i++ {
		bodySearchKMP(body, sha1Last)
	}
}

func Benchmark_bodySearchIndex(b *testing.B) {

	//sum := sha1.Sum([]byte("correct horse batt$ery staple"))
	sum := sha1.Sum([]byte("1234"))
	sumString := strings.ToUpper(fmt.Sprintf("%x", sum))

	sha1FirstFive := sumString[:5]
	sha1Last := sumString[5:]

	body, _ := rangeRequest(sha1FirstFive)

	for i := 0; i < b.N; i++ {
		bodySearchIndex(body, sha1Last)
	}
}
