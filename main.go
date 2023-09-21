package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/ventu-io/slog"
)

var secretKey = []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256
var logger = slog.New()

type Message struct {
	Text string `json:"text"`
}

func encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(ciphertext[aes.BlockSize:], []byte(plainText))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
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

	return string(ciphertext), nil
}

func main() {
	app := fiber.New()

	// Use Fiber's logger middleware
	app.Use(logger.New())

	app.Post("/encrypt", func(c *fiber.Ctx) error {
		var message Message
		if err := c.BodyParser(&message); err != nil {
			logger.Error(err)
			return c.Status(400).SendString("Failed to parse JSON")
		}

		if message.Text == "" {
			return c.Status(400).SendString("text is required")
		}

		encryptedText, err := encrypt(message.Text)
		if err != nil {
			logger.Error(err)
			return c.Status(500).SendString(err.Error())
		}

		return c.JSON(fiber.Map{"encrypted": encryptedText})
	})

	app.Post("/decrypt", func(c *fiber.Ctx) error {
		var message Message
		if err := c.BodyParser(&message); err != nil {
			logger.Error(err)
			return c.Status(400).SendString("Failed to parse JSON")
		}

		if message.Text == "" {
			return c.Status(400).SendString("encrypted text is required")
		}

		decryptedText, err := decrypt(message.Text)
		if err != nil {
			logger.Error(err)
			return c.Status(500).SendString(err.Error())
		}

		return c.JSON(fiber.Map{"decrypted": decryptedText})
	})

	log.Fatal(app.Listen(":3050"))
}
