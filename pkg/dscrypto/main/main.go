/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/12/4 18:40
*/

// 生成 AESencryptCode

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/base64"
	"fmt"
)

func main() {
	VpsIP := "172.26.216.10"                     //修改成自己的vps IP地址
	AESKey := "d05b1335ffe14d6b5d058272462b39c5" //修改成自己的AESkey
	encryptCode := AesEncrypt(VpsIP, AESKey)
	fmt.Println(encryptCode)
	decrptCode := AesDecrypt(encryptCode, AESKey)
	fmt.Println(decrptCode)
	//encryptCode2, _ := rc4Encrypt(AESKey, VpsIP)
	//fmt.Println(encryptCode2)
	//decryptCode, _ := rc4Decrypt(AESKey, string(encryptCode2))
	//fmt.Println(decryptCode)

}
func AES() {
	encryptCode := AesEncrypt("172.26.216.10", "d05b1335ffe14d6b5d058272462b39c5")
	fmt.Println(encryptCode)
}

func AesEncrypt(orig string, key string) string {
	// 转成字节数组
	origData := []byte(orig)
	k := []byte(key)

	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	origData = PKCS7Padding(origData, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)

	return base64.StdEncoding.EncodeToString(cryted)

}

func AesDecrypt(cryted string, key string) string {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)

	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	blockMode.CryptBlocks(orig, crytedByte)
	// 去补全码
	orig = PKCS7UnPadding(orig)
	return string(orig)
}

// PKCS7Padding 补码
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding 去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

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
