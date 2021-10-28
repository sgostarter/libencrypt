package aes

import (
	"crypto/aes"
	"errors"
)

var errCrash = errors.New("crash")

func ECBEncrypt(origData, key []byte) (encryptedData []byte, err error) {
	defer func() {
		if errR := recover(); errR != nil {
			err = errCrash
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	ecb := NewECBEncryptor(block)
	origData = PKCS5Padding(origData, block.BlockSize())
	encryptedData = make([]byte, len(origData))
	ecb.CryptBlocks(encryptedData, origData)

	return
}

func ECBDecrypt(encryptedData, key []byte) (origData []byte, err error) {
	defer func() {
		if errR := recover(); errR != nil {
			err = errCrash
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	ecb := NewECBDecrypter(block)
	origData = make([]byte, len(encryptedData))
	ecb.CryptBlocks(origData, encryptedData)
	origData, err = PKCS5UnPadding(origData)

	return
}
