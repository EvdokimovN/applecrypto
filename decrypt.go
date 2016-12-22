// Package applecrypto provides necseessray tools for working with ApplePay tokens
package applecrypto

// Decrypt tries do decrypt ApplePay Data field with provided certificate.
// Assumes certificate and privatekey are in the same file. Return decrypted data
func (at Token) Decrypt(filename, password string) ([]byte, error) {
	var decrypt []byte
	prk, cert, err := extractPrivateKey(filename, password)

	if err != nil {
		return decrypt, err
	}

	merchID, err := getMerchID(cert)

	if err != nil {
		return decrypt, err
	}

	pbk, err := generatePublicKey(at.Header.EphemeralPublicKey)

	if err != nil {
		return decrypt, err
	}

	secret, err := computeSecret(pbk, prk.D.Bytes())
	if err != nil {
		return decrypt, err
	}

	aesKey := restoreSymmetricKey(merchID, secret)
	decrypt, err = decryptData(aesKey, at.Data)
	return decrypt, err
}
