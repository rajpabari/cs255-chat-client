'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    let egKeyPair = await generateEG()
    this.EGKeyPair = egKeyPair
    const certificate = { "username": username, "pub": egKeyPair.pub }
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate(certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    if (verifyWithECDSA(this.caPublicKey, certString, signature)) {
      this.certs[certificate.username] = certificate
    }
    else {
      throw new Error('Invalid signature!')
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage(name, plaintext) {

    if (!(name in this.conns)) {
      const egKeyPair = await generateEG();
      const sharedSecret = await computeDH(egKeyPair.sec, this.certs.pub);
      this.conns.name = { "egKeyPair": egKeyPair, "sharedSecret": sharedSecret };
    }
    const header = { 'pub': this.conns.name.egKeyPair.pub, "iv": genRandomSalt(), "vGov": "", "cGov": "" };
    const hkdfEncryptionKey = await HKDF(this.conns.name.sharedSecret, await HMACtoHMACKey(header.iv), "ratchet-str");
    //note hkdf[0] is the new KDF and hkdf[1] is the new message key
    //encrypt message
    const aesKey = await HMACtoAESKey(hkdfEncryptionKey[1]);
    const ciphertext = await encryptWithGCM(aesKey, plaintext, header.iv);

    //store sending chain key
    this.conns.name["sendingChainKey"] = hkdfEncryptionKey[0];
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage(name, [header, ciphertext]) {
    throw ('not implemented!')
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
