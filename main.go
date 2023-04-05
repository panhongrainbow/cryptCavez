package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func main() {
	plaintext := []byte("my secret message")

	// 生成一個 256 位長度的隨機密鑰
	key := make([]byte, 32)
	fmt.Println(string(key))
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	// 創建一個新的 AES 密碼學區塊
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 使用 GCM 模式加密
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// 隨機生成一個 12 字節的 nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// 加密明文
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// 將密鑰和密文一起存儲，以便稍後解密
	encryptedData := append(nonce, ciphertext...)
	fmt.Println(string(encryptedData))

	// 解密
	decryptedData, err := decrypt(key, encryptedData)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted message: %s\n", decryptedData)
}

func decrypt(key, data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// 使用密鑰創建一個新的 AES 密碼學區塊
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 從密文中提取 nonce
	nonce := data[:12]

	// 創建一個新的 GCM 密碼學區塊
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 解密密文
	plaintext, err := aead.Open(nil, nonce, data[12:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
