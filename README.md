# pwned-search

Yes, I know it's been done before. pwned-search is a CLI
program that uses the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords)
range API to check if an input password has been leaked before.

This implementation addresses issues with other implementations:

 - passwords are entered into the CLI as a parameter to the program e.g. ```./pwned-search password1```
leaving a plaintext password in the terminal's history file without special
configuration.
 - General inefficiency in handling data that returns from HIBP. This implementation
parsing of the response and search in optimal time.
 - Unix-like interface. Support for piping, output is simple

# Building and Running

```bash
$ git clone https://github.com/yourusername/pwned-search.git
$ cd pwned-search
$ go build -o pwned-search
```

## Running from the CLI

```bash
$ ./pwned-search
enter a password:
403640
$
```

## Running from a script

```bash
$ cat mypwds.txt | ./pwned-search
3888677
```
