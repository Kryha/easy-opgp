const crypto    = require('./index.js');
/**
 * Test all functions within encryption class
 */
const test =  async function() {
    var passphrase  = 'super long and hard to guess secret';  //what the privKey is encrypted with
    var passphrase2 = 'super long and hard to guess secret2'; //what the privKey is encrypted with
    var passphrase3 = 'super long and hard to guess secret3'; //what the privKey is encrypted with
    var data        = 'Hello world'
    var data2       = 'Encrypted message'
    
    // generate keypairs
    var keypair     = await crypto.createKeyPair('blabla', 'blabla@blabla.bla', passphrase);
    var keypair2    = await crypto.createKeyPair('bla2', 'bla2@bla.bla', passphrase2);
    var keypair3    = await crypto.createKeyPair('bla3', 'bla3@bla.bla', passphrase3)

    // encrypt message
    var msg         = await crypto.encrypt(data, [keypair.publicKey, keypair2.publicKey]);
    
    //decrypt message using single keypair
    var decrypted1  = await crypto.decrypt(msg, keypair.privateKey, passphrase);    
    var decrypted2  = await crypto.decrypt(msg, keypair2.privateKey, passphrase2)
    

    // encrypt and sign
    var signedMsg   = await crypto.encryptAndSign(data2, [keypair.publicKey, keypair2.publicKey], [keypair.privateKey, keypair2.privateKey], [passphrase, passphrase2]);
    var verifiedMsg = await crypto.decryptAndVerify(signedMsg, [keypair.publicKey, keypair2.publicKey], keypair2.privateKey, passphrase2)
    
    // re-encrypt for different keypair and attach signatures
    var msg2        = {
        data: await crypto.encrypt(verifiedMsg.data, [keypair3.publicKey]),
        signature: signedMsg.signature
    }

    // decrypt and verify newly encrypted msg with new keypair
    var verifiedMsg2 = await crypto.decryptAndVerify(msg2, [keypair.publicKey, keypair2.publicKey], keypair3.privateKey, passphrase3)

    // verify signature using decrypted data and public key
    var valid       = await crypto.verify(data2, signedMsg, [keypair.publicKey, keypair2.publicKey, keypair3.publicKey])
    var valid2      = await crypto.verify(data2, msg2, [keypair.publicKey, keypair2.publicKey, keypair3.publicKey])


    // log result
    console.log('Results decryption:', '\r\n\tUsing kp1:', decrypted1, '\r\n\tUsing kp2:', decrypted2)
    console.log('\r\n\r\nResults verification and decryption:', '\r\n\tValidity signature kp1:', verifiedMsg.signatures[0].valid, '\r\n\tValidity signature kp2:', verifiedMsg.signatures[1].valid  )
    console.log('\r\n\r\nResults verification and decryption after re-encrypting for different pubkey with same signatures:', '\r\n\tValidity signature kp1:', verifiedMsg2.signatures[0].valid, '\r\n\tValidity signature kp2:', verifiedMsg2.signatures[1].valid  )        
    console.log('\r\n\r\nResults verification using only pubkey and unencrypted data:', '\r\n\tValidity signature kp1:', valid.signatures[0].valid, '\r\n\tValidity signature kp2:', valid.signatures[1].valid  )
    console.log('\r\n\r\nResults verification using only pubkey and unencrypted data after re-encrypting for different pubkey with same signatures:', '\r\n\tValidity signature kp1:', valid2.signatures[0].valid, '\r\n\tValidity signature kp2:', valid2.signatures[1].valid  )        

}

test()
