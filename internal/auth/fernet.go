package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const fernetVersion byte = 0x80

func fernetEncrypt(signingKey, encryptionKey, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generate fernet iv: %w", err)
	}
	padded := pkcs7Pad(plain, block.BlockSize())
	body := make([]byte, 1+8+len(iv)+len(padded))
	body[0] = fernetVersion
	binary.BigEndian.PutUint64(body[1:9], uint64(time.Now().Unix()))
	copy(body[9:9+len(iv)], iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(body[9+len(iv):], padded)
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(body)
	raw := append(body, mac.Sum(nil)...)
	token := make([]byte, base64.URLEncoding.EncodedLen(len(raw)))
	base64.URLEncoding.Encode(token, raw)
	return token, nil
}

func fernetDecrypt(signingKey, encryptionKey, token []byte) ([]byte, error) {
	raw := make([]byte, base64.URLEncoding.DecodedLen(len(token)))
	n, err := base64.URLEncoding.Decode(raw, token)
	if err != nil {
		return nil, fmt.Errorf("decode fernet token: %w", err)
	}
	token = raw[:n]
	const minLen = 1 + 8 + aes.BlockSize + aes.BlockSize + sha256.Size
	if len(token) < minLen || token[0] != fernetVersion {
		return nil, fmt.Errorf("invalid fernet token")
	}
	macStart := len(token) - sha256.Size
	expected := hmac.New(sha256.New, signingKey)
	_, _ = expected.Write(token[:macStart])
	if subtle.ConstantTimeCompare(expected.Sum(nil), token[macStart:]) != 1 {
		return nil, fmt.Errorf("invalid fernet signature")
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	ivStart := 1 + 8
	iv := token[ivStart : ivStart+aes.BlockSize]
	ciphertext := token[ivStart+aes.BlockSize : macStart]
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid fernet ciphertext")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return pkcs7Unpad(plain, block.BlockSize())
}

func pkcs7Pad(plain []byte, blockSize int) []byte {
	padding := blockSize - len(plain)%blockSize
	return append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(plain []byte, blockSize int) ([]byte, error) {
	if len(plain) == 0 || len(plain)%blockSize != 0 {
		return nil, fmt.Errorf("invalid fernet padding")
	}
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > blockSize || padding > len(plain) {
		return nil, fmt.Errorf("invalid fernet padding")
	}
	if !bytes.Equal(plain[len(plain)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		return nil, fmt.Errorf("invalid fernet padding")
	}
	return plain[:len(plain)-padding], nil
}
