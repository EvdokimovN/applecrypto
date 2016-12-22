# AppleCrypto: library for working with ApplePay

AppleCrypto is a simple library for decrypting ApplePay tokens as [described](https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html) by Apple written in GO.

Library provides only methods for decrypting and encrypting token as well as datatypes neccesery for working with Apple Paymnet Token. 

*Implementation seems to be a little bit naive and you probably shouldn't be using it in prodcution*


## Basic Usage

First initialise `Token` which is responsible for cryptographic operations

```
t, err := applecrypto.MakeToken(token)
```

> Error is thrown if provided token is not base64 encoded or cannot be unmarshaled in `Token` struct


Then simply call `Decrypt()` and pass it pass to file which contains certificate with private key and its password. 

> `Decrypt` implements steps 3-4 in Apple reference documentation

Library provides `Card` type for Unmarshalling decrypted data into.


*Author: Nikita Evdokimov*
