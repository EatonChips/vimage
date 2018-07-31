package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/goodgravy/stegano/image"
	tui "github.com/marcusolsson/tui-go"
	"golang.org/x/crypto/ssh/terminal"
)

const validHeader = "imgim"

var (
	imgPath string
	wipe    bool
)

func init() {
	flag.BoolVar(&wipe, "init", false, "Initialize the file")

	flag.Parse()

	imgPath = flag.Args()[0]

	if len(flag.Args()) < 1 {
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	key := make([]byte, 0)
	locked := true
	encHeader := ""

	if wipe {
		fmt.Print("Enter password to encrypt file: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		check(err)

		key = []byte(hash(string(bytePassword)))

		clearFile(key, imgPath)
		// os.Exit(0)
	}

	// Get text in the image
	text := image.RevealTextInImage(imgPath)

	// Loop until correct key is provided
	for locked {
		key = getKey()

		fmt.Println("")

		// Get and validate header
		encHeader = strings.Split(text, ":")[0]
		header, err := decrypt(key, encHeader)
		check(err)

		if header == validHeader {
			locked = false
		}

	}

	// Decrypt text
	encContent := strings.Split(text, ":")[1]
	content, err := decrypt(key, encContent)
	check(err)

	buffer := tui.NewTextEdit()
	buffer.SetSizePolicy(tui.Expanding, tui.Expanding)
	buffer.SetText(content)
	buffer.SetFocused(true)
	buffer.SetWordWrap(true)

	status := tui.NewStatusBar(imgPath)

	root := tui.NewVBox(buffer, status)

	ui, err := tui.New(root)
	check(err)

	ui.SetKeybinding("Esc", func() {
		encryptedText, err := encrypt(key, buffer.Text())
		check(err)

		image.HideStringInImage(encHeader+":"+encryptedText, imgPath, imgPath)
		ui.Quit()
	})

	if err := ui.Run(); err != nil {
		log.Fatal(err)
	}
}

func getKey() []byte {
	// Get password
	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	check(err)

	// Generate key
	key := []byte(hash(string(bytePassword)))

	return key
}

func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	// encmess = base64.StdEncoding.EncodeToString(cipherText)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	if len(securemess) == 0 {
		decodedmess = ""
		return
	}

	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		err = nil
		decodedmess = ""
		clearFile(key, imgPath)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

// Check for errors and quit if an error occured.
func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func hash(str string) (hash string) {
	hasher := md5.New()
	hasher.Write([]byte(str))

	return hex.EncodeToString(hasher.Sum(nil))
}

func clearFile(key []byte, imgPath string) {
	header, err := encrypt(key, validHeader)
	check(err)

	image.HideStringInImage(header+":", imgPath, imgPath)
}
