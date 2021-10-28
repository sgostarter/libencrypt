package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

var errOverflow = errors.New("pkcs5 unpadding overflow")

func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize

	return append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func PKCS5UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unPadding := int(origData[length-1])
	if length < unPadding {
		return nil, errOverflow
	}

	return origData[:(length - unPadding)], nil
}

func CBCEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher failed: %w", err)
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)

	return crypted, nil
}

func CBCDecrypt(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher failed: %w", err)
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(encryptedData))
	blockMode.CryptBlocks(origData, encryptedData)

	return PKCS5UnPadding(origData)
}
