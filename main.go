package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

type Creds struct {
	Website  string `json:"website"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	secret := os.Getenv("SECRET")
	if secret == "" {
		fmt.Println("SECRET environment variable not set.")
		return
	}
	// Create or open a JSON file for reading and writing.
	filename := "secret.json"
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
		return
	}
	defer file.Close()

	// Read the existing JSON data from the file.
	jsonData, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading JSON data from file:", err)
		return
	}

	var creds []Creds
	// Unmarshal the existing JSON data into a slice of Person structs.
	_ = json.Unmarshal(jsonData, &creds)


	//flags
	website := flag.String("website", "", "Enter the website")
	email := flag.String("email", "", "Enter your email")
	password := flag.String("password", "", "Enter your password")
	get := flag.String("get", "", "Get website data")
	flag.Parse()

	if *get != "" {
		var websiteCreds Creds
		for _, singleWebsite := range creds {
			if singleWebsite.Website == *get {
				websiteCreds = singleWebsite
				pass, _ := decrypt([]byte(secret), []byte(websiteCreds.Password))
				mail, _ := decrypt([]byte(secret), []byte(websiteCreds.Email))
				websiteCreds.Password = string(pass)
				websiteCreds.Email = string(mail)
				fmt.Println(websiteCreds)
				return
			}
			
		}
		fmt.Println("Not found")
	}

	if *website != "" && *email != "" && *password != "" {
		encryptedPassword, err := encrypt([]byte(secret), []byte(*password))
		if err != nil {
			fmt.Println(err)
		}
		encryptedEmail, err := encrypt([]byte(secret), []byte(*email))
		if err != nil {
			fmt.Println(err)
		}
		newCreds := Creds{
			Website:  *website,
			Email:    string(encryptedEmail),
			Password: string(encryptedPassword),
		}
		for _, singleWebsite := range creds {
			if singleWebsite.Website == newCreds.Website {
				fmt.Println("Website exists")
				return
			}
		}
		creds = append(creds, newCreds)

		// Marshal the updated slice back to JSON.
		updatedJSON, err := json.MarshalIndent(creds, "", "  ")
		if err != nil {
			fmt.Println("Error marshaling updated data to JSON:", err)
			return
		}

		// Write the updated JSON data back to the file.
		if err := os.WriteFile(filename, updatedJSON, os.ModePerm); err != nil {
			fmt.Println("Error writing updated JSON data to file:", err)
			return
		}
	}
}

// Encrypt encrypts data using the provided secret key.
func encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], data)

	// Encode the ciphertext using a custom base64 encoding with no symbols.
	encodedCiphertext := base64.RawURLEncoding.EncodeToString(ciphertext)

	return []byte(encodedCiphertext), nil
}

// Decrypt decrypts data using the provided secret key.
func decrypt(key, data []byte) ([]byte, error) {
	// Decode the custom base64 encoded ciphertext.
	decodedCiphertext, err := base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(decodedCiphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := decodedCiphertext[:aes.BlockSize]
	decodedCiphertext = decodedCiphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(decodedCiphertext, decodedCiphertext)

	return decodedCiphertext, nil
}
