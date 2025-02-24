package dscrypto

import (
	"crypto/rc4"
)

func rc4Encrypt(k string, plaint string) ([]byte, error) {
	key := []byte(k)
	plaintext := []byte(plaint)

	ciphertext := make([]byte, len(plaintext))

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func rc4Decrypt(k string, ciphert string) ([]byte, error) {

	key := []byte(k)
	ciphertext := []byte(ciphert)

	plaintext := make([]byte, len(ciphertext))
	cipher, err := rc4.NewCipher(key)

	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
