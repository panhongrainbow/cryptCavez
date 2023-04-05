package aesz

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

const (
	ErrAtLeastOneBlock = Error("the ciphertext is at least one block size")
)

type Error string

func (e Error) Error() string {
	return string(e)
}

// Encrypt uses AES-GCM with nonce and key to encrypt plaintext data.
func Encrypt(key, plaintext []byte) (encryptedData []byte, err error) {
	/*
		AES is a block cipher encryption algorithm that divides plaintext data into fixed-size blocks (usually 128 bits) and encrypts each block individually.
		This block cipher encryption method improves encryption efficiency and enhances the security of data.
	*/
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	/*
		GCM mode encryption is a method of encryption that provides both security and integrity of information.
		It combines two techniques: Counter mode and GMAC message authentication code, to provide stronger security.
		- GMAC message authentication code is a technique that ensures that information is not tampered with during transmission.
		- Counter mode is a method of encryption that ensures that a different keystream is used for each encryption, thereby improving security.
	*/
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	/*
		A replay attack is a type of network attack where the attacker intercepts encrypted information and then resends it at a later time,
		such as repeatedly transferring money from a bank account.
		Many encryption protocols use nonce or other methods to ensure that each received message is fresh.
	*/
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}

	// Encrypt using the AES algorithm for final encryption
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	/*
		Storing nonce key and ciphertext together is possible
		because nonce key primarily serves to prevent replay attacks.
	*/
	encryptedData = append(nonce, ciphertext...)

	// Return the encryptedData and err values
	return
}

// Decrypt decrypts ciphertext using AES-GCM with nonce and key.
func Decrypt(key, data []byte) (plaintext []byte, err error) {
	// Ensure that the length of the ciphertext is at least one block size
	if len(data) < aes.BlockSize {
		err = ErrAtLeastOneBlock
		return
	}

	// Create a new AES cipher using the provided key
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	// Extract the nonce from the beginning of the ciphertext
	nonce := data[:12]

	// Create a new Galois/Counter Mode (GCM) instance using the AES cipher
	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	// Decrypt the ciphertext using the GCM instance and nonce, and obtain the plaintext
	plaintext, err = aead.Open(nil, nonce, data[12:], nil)
	if err != nil {
		return
	}

	// Return the plaintext and nil error
	return
}
