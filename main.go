package main

import (
	"bytes"
	"fmt"
	"os"
	"sef-comp/file-encrypt/fliecrypt"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)

	}
	function := os.Args[1]
	switch function {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	}
}

func decryptHandle() {
	if len(os.Args) < 3 {
		fmt.Println("Missing path to file")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		panic("File not found")
	}
	fmt.Print("Enter password:")
	password, _ := terminal.ReadPassword(0)
	fmt.Println("\nDecrypting...")
	fliecrypt.Decrypt(file, password)
	fmt.Println("\nFile successfully decrypted")
}

func encryptHandle() {
	if len(os.Args) < 3 {
		fmt.Println("Missing path to file")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		panic("File not found")
	}
	password := getPassword()
	fmt.Println("\nEncrypting...")
	fliecrypt.Encrypt(file, password)
	fmt.Println("\nFile successfully encrypted")
}

func printHelp() {
	fmt.Println("File-Encrypter")
	fmt.Println("\nUsage: ./file-encrypter <function> <path to file>")
	fmt.Println("\nCommands:")
	fmt.Println("\thelp - displays text help")
	fmt.Println("\tencrypt - encrypts file")
	fmt.Println("\tdecrypt - decrypts file")
}

func getPassword() []byte {
	fmt.Print("Enter password:")
	password, _ := terminal.ReadPassword(0)
	fmt.Print("\nConfirm password:")
	password2, _ := terminal.ReadPassword(0)
	if !validatePassword(password, password2) {
		fmt.Println("\nPasswords do not match")
		return getPassword()
	}
	return password
}

func validatePassword(p1 []byte, p2 []byte) bool {
	return bytes.Equal(p1, p2)
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}
