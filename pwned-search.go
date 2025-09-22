package main

import (
	"bufio"
	"cmp"
	"crypto/sha1"
	"fmt"
	"golang.org/x/term"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
)

func readPwd(prompt string) ([]byte, error) {

	fmt.Printf(prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pwd, err := term.ReadPassword(fd)
		return pwd, err
	} else {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadBytes('\n')
		return line[:len(line)-1], err
	}
}

// pwned-search is my implementation of the HaveIBeenPwned range password checker
// the program takes as input one of your passwords, and checks the API to see
// if it has been in any leak. Your password is never sent to the API or a third party
// Passwords are read via a prompt, so they are not part of the terminal's history
func main() {

	pwd, err := readPwd("enter a password:\n")

	if err != nil {
		log.Fatal(err)
	}

	sum := sha1.Sum(pwd)
	sumString := strings.ToUpper(fmt.Sprintf("%x", sum))
	firstFive := sumString[:5]
	last := sumString[5:]

	res, err := http.Get("https://api.pwnedpasswords.com/range/" + firstFive)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(res.Body)

	if res.StatusCode >= 299 {
		log.Fatalf("Response failed with status code: %d and\nbody: %s\n", res.StatusCode, body)
	}

	if err != nil {
		log.Fatal(err)
	}

	err = res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	// regex is fairly slow, because we get a sorted list in return. A faster way would be to split body by line
	// and binary search the first part of it.
	// adding to a map would still require splitting, but is possible to do it in one pass.
	// using begin/end indexes in the original byte array?
	hashes := strings.Split(string(body), "\n")

	i, found := slices.BinarySearchFunc(hashes, last, func(a string, b string) int {
		// using custom function to ignore the part of the string with colon
		// splitting is relatively inexpensive because it is performed on lgn compares
		as := strings.Split(a, ":")
		bs := strings.Split(b, ":")

		return cmp.Compare(as[0], bs[0])
	})

	if !found {
		fmt.Printf("0\n")
	} else {
		count := strings.Split(hashes[i], ":")[1]
		// process extra because count has a carriage return, or maybe just print the count?
		fmt.Printf("%s\n", count)
	}
}
