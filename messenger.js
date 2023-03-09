"use strict";

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
  govEncryptionDataStr,
} = require("./lib");

/** ******* Implementation ********/

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = {}; // keypair from generateCertificate
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
    let egKeyPair = await generateEG();
    this.EGKeyPair = egKeyPair;
    const certificate = { username: username, pub: egKeyPair.pub };
    return certificate;
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
    const certString = JSON.stringify(certificate);
    if (await verifyWithECDSA(this.caPublicKey, certString, signature)) {
      this.certs[certificate.username] = certificate;
    } else {
      throw new Error("Invalid signature!");
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
      const RK = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
      this.conns.name = { RK: RK, DHr: this.certs[name].pub };
    }

    const A1 = await HMACtoAESKey(this.conns.name.CKs, govEncryptionDataStr);
    this.conns.name.CKs = await HMACtoHMACKey(this.conns.name.CKs, "HMACKeyGen");

    const iv = genRandomSalt();
    const ciphertext = await encryptWithGCM(A1, plaintext, iv);

    const header = { receiverIV: iv, pub: this.EGKeyPair.pub, "vGov": "", "cGov": "", "ivGov": "" }
    return [header, ciphertext];
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
    // compare the public key header with the public key in the connection DHr
    // if they are not the same, then we need to recompute the ratchet (use flag )
    if (!(name in this.conns)) {
      const RK = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
      this.conns.name = { RK: RK, DHr: header.pub };
    }

    if (header.pub !== this.conns.name.DHr) {

      this.EGKeyPair = await generateEG();
      const hkdfOutputRatchet = await HKDF(
        this.conns.name.RK,
        await computeDH(this.EGKeyPair.sec, this.conns.name.DHr),
        "ratchet-str"
      );
      this.conns.name.RK = hkdfOutputRatchet[0];
      this.conns.name.CKs = hkdfOutputRatchet[1];
      this.conns.name.ratchetComputed = true;
    }

    return plaintext;
  }
}

module.exports = {
  MessengerClient,
};
