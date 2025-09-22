package main

import (
	"bufio"
	"cmp"
	"crypto/sha1"
	"fmt"
	"github.com/a-tk/go-algorithms/strmatch"
	"golang.org/x/term"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
)

func readPwd() ([]byte, error) {

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Printf("enter a password:\n")
		pwd, err := term.ReadPassword(fd)
		return pwd, err
	} else {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadBytes('\n')
		return line[:len(line)-1], err
	}
}

func rangeRequest(sha1FirstFive string) (body []byte, err error) {

	res, err := http.Get("https://api.pwnedpasswords.com/range/" + sha1FirstFive)
	if err != nil {
		return body, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(res.Body)

	body, err = io.ReadAll(res.Body)

	if res.StatusCode > 299 {
		log.Fatalf("Response failed with status code: %d and\nbody: %s\n", res.StatusCode, body)
	}
	return body, err
}

// given a body of bytes, parse and return a string representation of the count
// string representation because that is already the underlying format
func bodySearch(body []byte, sha1Last string) (count string, found bool) {

	// regex is fairly slow, because we get a sorted list from the API. A faster way would be to split body by line
	// and binary search the first part of it.
	// adding to a map would still require splitting, but is possible to do it while reading the body
	// using begin/end indexes in the original byte array
	hashes := strings.Split(string(body), "\n")

	// each line looks like 1234FDA....1234A:1
	// using custom function to ignore the part of the string with colon
	// splitting is relatively inexpensive because it is performed on lgn compares
	i, found := slices.BinarySearchFunc(hashes, sha1Last, func(a string, b string) int {
		as := strings.Split(a, ":")
		bs := strings.Split(b, ":")
		return cmp.Compare(as[0], bs[0])
	})

	if !found {
		return count, false
	} else {
		count = strings.Split(hashes[i], ":")[1]
		return count, true
	}
}

func bodySearchKMP(body []byte, sha1Last string) (count string, found bool) {

	i, found := strmatch.StrMatchKmpFirst(body, sha1Last)
	if found {
		// get the count by counting from the colon to the newline
		endOfLine := i + len(sha1Last) // end of line occurs at newline or EOF
		for endOfLine < len(body) && body[endOfLine] != '\n' {
			endOfLine++
		}
		return string(body[i+len(sha1Last)+2 : endOfLine-1]), true
	} else {
		return count, false
	}
}

func bodySearchIndex(body []byte, sha1Last string) (count string, found bool) {

	i := strings.Index(string(body), sha1Last)
	if i != -1 {
		// get the count by counting from the colon to the newline
		endOfLine := i + len(sha1Last) // end of line occurs at newline or EOF
		for endOfLine < len(body) && body[endOfLine] != '\n' {
			endOfLine++
		}
		return string(body[i+len(sha1Last)+1 : endOfLine-1]), true
	} else {
		return count, false
	}
}

// pwned-search is my implementation of the HaveIBeenPwned range password checker
// the program takes as input one of your passwords, and checks the API to see
// if it has been in any leak. Your password is never sent to the API or a third party
// Passwords are read via a prompt, so they are not part of the terminal's history
func main() {

	pwd, err := readPwd()

	if err != nil {
		log.Fatal(err)
	}

	sum := sha1.Sum(pwd)
	sumString := strings.ToUpper(fmt.Sprintf("%x", sum))

	sha1FirstFive := sumString[:5]
	sha1Last := sumString[5:]

	body, err := rangeRequest(sha1FirstFive)

	count, found := bodySearchKMP(body, sha1Last)

	if !found {
		fmt.Printf("0\n")
	} else {
		fmt.Printf("%s\n", count)
	}
}
