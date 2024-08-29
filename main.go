package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Content struct {
	Label    string `json:"label"`
	Password string `json:"password"`
}

type Data struct {
	Content []Content `json:"content"`
	Secret  string    `json:"secret"`
}

func GenerateSecret() string {
	secret := make([]byte, 16)
	rand.Read(secret)
	return base64.StdEncoding.EncodeToString(secret)
}

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	// Generate a new random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, iv)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)

	// Prepend the IV to the ciphertext
	return Encode(append(iv, cipherText...)), nil
}

func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	cipherText := Decode(text)

	// Extract the IV from the beginning of the ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)

	return string(plainText), nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: crypter <json_file>")
		return
	}

	jsonFilePath := os.Args[1]
	jsonFile, err := os.Open(jsonFilePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var data Data
	json.Unmarshal(byteValue, &data)

	if data.Secret != "" {
		secret := data.Secret
		for i, content := range data.Content {
			decryptedPassword, err := Decrypt(content.Password, secret)
			if err != nil {
				fmt.Println(err)
				return
			}
			data.Content[i].Password = decryptedPassword
		}
		data.Secret = ""
	} else {
		secret := GenerateSecret()
		data.Secret = secret
		for i, content := range data.Content {
			encryptedPassword, err := Encrypt(content.Password, secret)
			if err != nil {
				fmt.Println(err)
				return
			}
			data.Content[i].Password = encryptedPassword
		}
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = os.WriteFile(jsonFilePath, jsonData, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	if data.Secret == "" {
		fmt.Printf("Passwords decrypted and secret removed from %s\n", jsonFilePath)
	} else {
		fmt.Printf("Passwords encrypted and secret added to %s\n", jsonFilePath)
	}
}
