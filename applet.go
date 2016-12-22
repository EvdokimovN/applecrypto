// Package applecrypto provides necseessray tools for working with ApplePay tokens
package applecrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/pkcs12"
)

// extractPrivateKey assumes file containts both PrivateKey and Certificate
func extractPrivateKey(filename, password string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	privateKey, cerf, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, nil, err
	}

	pkbyte := privateKey.(*ecdsa.PrivateKey)

	return pkbyte, cerf, nil
}

// getMerchID extracts MerchantId field from certificate
func getMerchID(cert *x509.Certificate) ([]byte, error) {
	var merchID []byte
	var merch []byte

	for _, e := range cert.Extensions {
		id := e.Id.String()
		if id == oIDMerchantID {
			merch = e.Value
		}
	}

	if len(merch) != 66 {
		return merchID, errors.New("merchantId is not 66 bytes long")
	}

	merch = merch[2:]
	merchID, err := hex.DecodeString(string(merch))
	if err != nil {
		return merchID, err
	}

	return merchID, nil
}

func generatePublicKey(base string) (*ecdsa.PublicKey, error) {
	var pbkey *ecdsa.PublicKey
	block, _ := pem.Decode([]byte("-----BEGIN PUBLIC KEY-----\n" + base + "\n-----END PUBLIC KEY-----"))

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return pbkey, err
	}

	pbkey = pubKey.(*ecdsa.PublicKey)

	return pbkey, nil
}

func computeSecret(pbk *ecdsa.PublicKey, prk []byte) ([]byte, error) {
	var secret []byte
	curve := elliptic.P256()

	if !curve.IsOnCurve(pbk.X, pbk.Y) {
		return secret, errors.New("point is not on curve")
	}

	x, _ := curve.ScalarMult(pbk.X, pbk.Y, prk)
	secret = x.Bytes()

	return secret, nil

}

// resotoreSymmetricKey using apple guidlines
func restoreSymmetricKey(merchID, secret []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte{0, 0, 0, 1})
	hasher.Write(secret)
	hasher.Write([]byte{13})
	hasher.Write([]byte("id-aes256-GCM"))
	hasher.Write([]byte("Apple"))
	hasher.Write([]byte(merchID))
	key := hasher.Sum(nil)
	return key
}

// decryptData AES decrypts data string using apple guidlines
func decryptData(aesKey []byte, data string) ([]byte, error) {
	var decrypted []byte
	iv := make([]byte, 16)

	dataDec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return decrypted, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return decrypted, err
	}
	d, _ := cipher.NewGCMWithNonceSize(block, len(iv))
	decrypted, err = d.Open(nil, iv, dataDec, nil)
	return decrypted, err
}

// encryptData AES encrypts data string using apple guidlines
func encryptData(aesKey []byte, data string) ([]byte, error) {
	var encrypted []byte
	iv := make([]byte, 16)

	dataEnc := []byte(data)

	block, err := aes.NewCipher(aesKey)
	e, _ := cipher.NewGCMWithNonceSize(block, len(iv))
	encrypted = e.Seal(nil, iv, []byte(dataEnc), nil)
	return encrypted, err
}
