# Global

Wrapper for OpenPGP package. Allows for easier use of OpenPGP encryption for basic use cases.

For implementation examples please refer to the testfile




* * *

## Class: OPGPClass


### OPGPClass.createKeyPair(name, email, passphrase) 

Creates a keypair

**Parameters**

**name**: `string`, name of keypair owner

**email**: `string`, email of keypair owner

**passphrase**: `string`, passphrase to decrypt private key

**Returns**: `Keypair`, - object containing armored public key and armored, encrypted private key

### OPGPClass.encrypt(data, publicKey) 

Encrypts data using public keys

**Parameters**

**data**: `string`, data to be encrypted

**publicKey**: `Array.<string>`, array of armored public keys used to encrypt data

**Returns**: `string`, - string containing armored encrypted message

### OPGPClass.decrypt(data, privateKey, passphrase) 

Decrypts data using private keys

**Parameters**

**data**: `string`, encrypted data to be decrypted

**privateKey**: `string`, armored, encrypted private key

**passphrase**: `string`, passphrase to decrypt private key

**Returns**: `string`, - returns string containing decrypted data

### OPGPClass.encryptAndSign(data, privkeys, pubkeys, passphrases) 

Encrypts data using public keys and signs using private keys

**Parameters**

**data**: `string`, data to be encrypted

**privkeys**: `Array.<string>`, array of armored encrypted private keys used to sign data

**pubkeys**: `Array.<string>`, array of armored public keys used to encrypt data

**passphrases**: `Array.<string>`, array of passphrases used to decrypt private keys

**Returns**: `SignedMsg`, - object containing armored signed encrypted message

### OPGPClass.decryptAndVerify(signedMsg, pubkeys, privkey, passphrase) 

Decrypts encrypted data using private key and validates detached signatures using public keys

**Parameters**

**signedMsg**: `SignedMsg`, signed and encrypted message to be decrypted and verified

**pubkeys**: `Array.<string>`, public keys to verify message against

**privkey**: `string`, private key used to decrypt message

**passphrase**: `Array.<string>`, passphrase to decrypt private key

**Returns**: `VerifiedMsg`

### OPGPClass.verify(rawData, signedMsg, pubkeys) 

Verifies data using signature and public key of signer

**Parameters**

**rawData**: `string`, string containing the data which the signature object signed

**signedMsg**: `SignedMsg`, encrypted message to verify

**pubkeys**: `string`, signature signer public key, used to verify signature




* * *










