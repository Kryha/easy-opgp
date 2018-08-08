function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var openpgp = require('openpgp'); // use as CommonJS, AMD, ES6 module or via window.openpgp

/**
 * Object containing crypto functions
 *
 * @typedef {object} Keypair
 * @property {string} publicKey - public key of keypair
 * @property {string} privateKey - private key of keypair
 * 
 * @typedef {object} SignedMsg
 * @property {string} data - string containing encrypted data
 * @property {string} signature - string containing signatures
 * 
 * @typedef {object} VerifiedMsg
 * @property {string} data - string containing encrypted data
 * @property {array.object} signature - array containing openpgp Signature objects showing validity of signature
 * 
 */
class OPGPClass {
    /**
     * Creates a keypair
     * @function
     * @param {string} name - name of keypair owner
     * @param {string} email - email of keypair owner
     * @param {string} passphrase - passphrase to decrypt private key
     * 
     * @returns {Keypair} - object containing armored public key and armored, encrypted private key
     */
    createKeyPair(name, email, passphrase) {
        return _asyncToGenerator(function* () {
            let options = {
                userIds: [{ name: name, email: email }], // multiple user IDs
                curve: "ed25519", // ECC curve name
                passphrase: passphrase // protects the private key
            };

            let key = yield openpgp.generateKey(options).catch(function (e) {
                console.error('Could not create keypair');
                throw e;
            });

            return {
                privateKey: key.privateKeyArmored,
                publicKey: key.publicKeyArmored
            };
        })();
    }

    _decryptPrivateKey(privKeyObj, passphrase) {
        return _asyncToGenerator(function* () {
            let success = yield privKeyObj.decrypt(passphrase).catch(function (error) {
                if (error.message === 'Key packet is already decrypted.') {
                    console.log('Already decrypted');
                    return true;
                } else {
                    console.log(error);
                    return error;
                }
            });

            if (success === true) {
                return privKeyObj;
            } else {
                throw success;
            }
        })();
    }

    /**
     * Encrypts data using public keys
     * @function
     * @param {string} data - data to be encrypted
     * @param {string[]} publicKey - array of armored public keys used to encrypt data
     * 
     * @returns {string} - string containing armored encrypted message
     */
    encrypt(data, pub) {
        return _asyncToGenerator(function* () {
            let kpArray = [];
            let temp;

            for (let i = 0; i < pub.length; i++) {
                temp = openpgp.key.readArmored(pub[i]);

                kpArray[i] = temp.keys[0];
            }
            let options = {
                data: data, // input as String (or Uint8Array)
                publicKeys: kpArray // for encryption
            };

            let ciphertext = yield openpgp.encrypt(options).catch(function (e) {
                console.error('Could not encrypt message in encrypt function');
                throw e;
            });

            return ciphertext.data;
        })();
    }

    /**
     * Decrypts data using private keys
     * @function
     * @param {string} data - encrypted data to be decrypted
     * @param {string} privateKey - armored, encrypted private key
     * @param {string} passphrase - passphrase to decrypt private key
     * 
     * @returns {string} - returns string containing decrypted data
     */
    decrypt(data, privateKey, passphrase) {
        var _this = this;

        return _asyncToGenerator(function* () {
            let privKeyObj = openpgp.key.readArmored(privateKey);

            privKeyObj = privKeyObj.keys[0];
            privKeyObj = yield _this._decryptPrivateKey(privKeyObj, passphrase);

            let message = openpgp.message.readArmored(data);

            let options = {
                message: message, // parse armored message
                privateKeys: [privKeyObj] // for decryption
            };

            let decrypted = yield openpgp.decrypt(options).catch(function (e) {
                console.error('Could not decrypt message in decrypt function');
                throw e;
            });
            return decrypted.data;
        })();
    }

    removeArmor(key, passphrase) {
        return _asyncToGenerator(function* () {

            let keyObj = openpgp.key.readArmored(key).keys[0];

            if (keyObj.isPrivate()) {
                yield keyObj.decrypt(passphrase).catch(function (err) {
                    console.log("Please provide correct passphrase");
                    throw err;
                });
            }

            let plainKey = keyObj.armor();

            // split on new lines
            plainKey = plainKey.split('\r\n').filter(function (v) {
                return v != '';
            });

            // filter out armor
            plainKey = plainKey.slice(3, plainKey.length - 1).join('');

            return plainKey;
        })();
    }

    /**
     * Encrypts data using public keys and signs using private keys
     * @function
     * @param {string} data - data to be encrypted
     * @param {Array.<string>} privkeys - array of armored encrypted private keys used to sign data
     * @param {Array.<string>} pubkeys - array of armored public keys used to encrypt data
     * @param {Array.<string>} passphrases - array of passphrases used to decrypt private keys
     * 
     * @returns {SignedMsg} - object containing armored signed encrypted message
     */
    encryptAndSign(data, pubkeys, privkeys, passphrases) {
        var _this2 = this;

        return _asyncToGenerator(function* () {
            let kpArray = [];
            let privKeyObjs = [];

            for (let i = 0; i < pubkeys.length; i++) {
                kpArray[i] = openpgp.key.readArmored(pubkeys[i]).keys[0];
            }

            for (let i = 0; i < privkeys.length; i++) {
                privKeyObjs[i] = openpgp.key.readArmored(privkeys[i]).keys[0];
                privKeyObjs[i] = yield _this2._decryptPrivateKey(privKeyObjs[i], passphrases[i]);
            }

            let options = {
                data: data, // input as String (or Uint8Array)
                publicKeys: kpArray, // for encryption
                privateKeys: privKeyObjs,
                // compression: openpgp.enums.compression.zip,
                detached: true
            };

            let encrypted = yield openpgp.encrypt(options).catch(function (e) {
                console.error('Could not encrypt message in encrypt and sign function');
                throw e;
            });

            return encrypted;
        })();
    }

    /**
     * Decrypts encrypted data using private key and validates detached signatures using public keys
     * @function
     * @param {SignedMsg} signedMsg - signed and encrypted message to be decrypted and verified
     * @param {string[]} pubkeys - public keys to verify message against
     * @param {string} privkey - private key used to decrypt message
     * @param {string[]} passphrase - passphrase to decrypt private key
     * 
     * @returns {VerifiedMsg}
     */
    decryptAndVerify(signedMsg, pubkeys, privkey, passphrase) {
        var _this3 = this;

        return _asyncToGenerator(function* () {
            let kpArray = [];
            let temp;

            for (let i = 0; i < pubkeys.length; i++) {
                kpArray[i] = openpgp.key.readArmored(pubkeys[i]).keys[0];
            }
            let privKeyObj = openpgp.key.readArmored(privkey).keys[0];
            privKeyObj = yield _this3._decryptPrivateKey(privKeyObj, passphrase);

            let message = openpgp.message.readArmored(signedMsg.data);

            let signature = openpgp.signature.readArmored(signedMsg.signature);

            let options = {
                message: message, // parse armored message
                privateKeys: [privKeyObj],
                publicKeys: kpArray,
                signature: signature,
                detached: true
            };

            let decrypted = yield openpgp.decrypt(options).catch(function (e) {
                console.error('Could not decrypt message in decrypt and verification function');
                throw e;
            });

            return decrypted;
        })();
    }

    /**
     * Verifies data using signature and public key of signer
     * @function
     * 
     * @param {string} rawData - string containing the data which the signature object signed
     * @param {SignedMsg} signedMsg - encrypted message to verify
     * @param {string} pubkeys - signature signer public key, used to verify signature
     */
    verify(rawData, signedMsg, pubkeys) {
        return _asyncToGenerator(function* () {
            let kpArray = [];
            let temp;

            for (let i = 0; i < pubkeys.length; i++) {
                kpArray[i] = openpgp.key.readArmored(pubkeys[i]).keys[0];
            }

            let message = openpgp.message.fromText(rawData);

            let signature = openpgp.signature.readArmored(signedMsg.signature);

            let options = {
                message: message,
                signature: signature,
                publicKeys: kpArray
            };

            let verification = yield openpgp.verify(options).catch(function (e) {
                console.error('Could not verify signature in verification function');
                throw e;
            });
            return verification;
        })();
    }
}
module.exports = new OPGPClass();