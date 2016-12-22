// Package applecrypto provides necseessray tools for working with ApplePay tokens
package applecrypto

import (
	"encoding/base64"
	"encoding/json"
)

// MakeToken creates applePay token instance
func MakeToken(token string) (Token, error) {
	var at Token

	sDec, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return at, err
	}

	err = json.Unmarshal([]byte(sDec), &at)
	return at, err
}

// Card represents Payment Data Keys as described by apple
type Card struct {
	AccountNumber string            `json:"applicationPrimaryAccountNumber"`
	ExpDate       string            `json:"applicationExpirationDate"` //Card expiration date in the format YYMMDD.
	Currency      string            `json:"currencyCode"`
	Amount        int               `json:"transactionAmount"`
	CardHolder    string            `json:"cardholderName"`
	DeviceManID   string            `json:"deviceManufacturerIdentifier"` //hex encoded
	PayDataType   string            `json:"paymentDataType"`              //Either 3DSecure or EMV.
	PayData       map[string]string `json:"paymentData"`
}

// Token represents base64 decoded ApplePay string
type Token struct {
	Header    headerToken
	Version   string
	Data      string
	Signature string
}

type headerToken struct {
	EphemeralPublicKey string
	PublicKeyHash      string
	TransactionID      string
}

const oIDMerchantID = "1.2.840.113635.100.6.32"
