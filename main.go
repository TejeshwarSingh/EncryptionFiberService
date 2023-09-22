package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"github.com/gofiber/fiber/v2"
)

var secretKey = []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256

type Message struct {
	Text string `json:"text"`
}

func pkcs7Padding(data []byte, blockSize int) []byte {
    padding := blockSize - len(data)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padtext...)
}


func encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	paddedPlainText := pkcs7Padding([]byte(plainText), block.BlockSize())

	ciphertext := make([]byte, aes.BlockSize+len(paddedPlainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(ciphertext[aes.BlockSize:], []byte(paddedPlainText))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func pkcs7Unpadding(data []byte) []byte {
    length := len(data)
    unpadding := int(data[length-1])
    return data[:(length - unpadding)]
}

func decrypt(cryptoText string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(ciphertext, ciphertext)

	decryptedBytes := pkcs7Unpadding(ciphertext)
	return string(decryptedBytes), nil
}

func main() {
	app := fiber.New()

	app.Post("/encrypt", func(c *fiber.Ctx) error {
		var message Message
		if err := c.BodyParser(&message); err != nil {
			log.Printf("Error: %v", err)
			return c.Status(400).SendString("Failed to parse JSON")
		}

		if message.Text == "" {
			return c.Status(400).SendString("text is required")
		}

		encryptedText, err := encrypt(message.Text)
		if err != nil {
			log.Printf("Error: %v", err)
			return c.Status(500).SendString(err.Error())
		}

		return c.JSON(fiber.Map{"encrypted": encryptedText})
	})

	app.Post("/decrypt", func(c *fiber.Ctx) error {
		var message Message
		if err := c.BodyParser(&message); err != nil {
			log.Printf("Error: %v", err)
			return c.Status(400).SendString("Failed to parse JSON")
		}

		if message.Text == "" {
			return c.Status(400).SendString("encrypted text is required")
		}

		decryptedText, err := decrypt(message.Text)
		if err != nil {
			log.Printf("Error: %v", err)
			return c.Status(500).SendString(err.Error())
		}

		return c.JSON(fiber.Map{"decrypted": decryptedText})
	})

	err := app.Listen(":3050")
	if err != nil {
		log.Fatalf("Failed to start the server: %v", err)
	}
}
