// Package applecrypto provides necseessray tools for working with ApplePay tokens
package applecrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// Encrypt encrypts data using provided cerificate. Returns base 64 encrypted data and ephemeral public key
func (at Token) Encrypt(filename, password string, in []byte) (string, string, error) {
	var ephem string
	var encS string

	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return encS, ephem, err
	}

	_, cert, err := extractPrivateKey(filename, password)
	if err != nil {
		return encS, ephem, err
	}

	eB := ephemeral.D.Bytes()
	pubkey := cert.PublicKey.(*ecdsa.PublicKey)

	// https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman
	x, _ := pubkey.Curve.ScalarMult(pubkey.X, pubkey.Y, eB)
	if x == nil {
		return encS, ephem, errors.New("failed to generate encryption key")
	}

	secret := x.Bytes()

	eB, err = x509.MarshalPKIXPublicKey(ephemeral.Public())
	if err != nil {
		return encS, ephem, err
	}

	merchID, err := getMerchID(cert)
	if err != nil {
		return encS, ephem, err
	}

	symmetricKey := restoreSymmetricKey(merchID, secret)
	enc, err := encryptData(symmetricKey, string(in))

	ephem = base64.StdEncoding.EncodeToString(eB)
	encS = base64.StdEncoding.EncodeToString(enc)

	return encS, ephem, err
}
