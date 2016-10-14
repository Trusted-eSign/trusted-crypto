import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {CryptoMethod} from "../crypto_method";
import {Key} from "./key";
import {CertificateCollection} from "./certs";
import {Certificate} from "./cert";
import {CmsRecipientInfoCollection} from "../cms/recipientInfos";

/**
 * Encrypt and decrypt operations
 *
 * @export
 * @class Cipher
 * @extends {object.BaseObject<native.PKI.Cipher>}
 */
export class Cipher extends object.BaseObject<native.PKI.Cipher> {

    /**
     * Creates an instance of Cipher.
     *
     *
     * @memberOf Cipher
     */
    constructor() {
        super();
        this.handle = new native.PKI.Cipher();
    }

    /**
     * Set crypto method
     *
     * @param method SYMMETRIC or ASSIMETRIC
     *
     * @memberOf Cipher
     */
    set cryptoMethod(method: CryptoMethod){
        this.handle.setCryptoMethod(method);
    }

    /**
     * Encrypt data
     *
     * @param {string} filenameSource This file will encrypted
     * @param {string} filenameEnc File path for save encrypted data
     * @param {DataFormat} [format]
     *
     * @memberOf Cipher
     */
    public encrypt(filenameSource: string, filenameEnc: string, format?: DataFormat): void {
        this.handle.encrypt(filenameSource, filenameEnc, format);
    }

    /**
     * Decrypt data
     *
     * @param {string} filenameEnc This file will decrypt
     * @param {string} filenameDec File path for save decrypted data
     * @param {DataFormat} [format]
     *
     * @memberOf Cipher
     */
    public decrypt(filenameEnc: string, filenameDec: string, format?: DataFormat): void {
        this.handle.decrypt(filenameEnc, filenameDec, format);
    }

    /**
     * Add recipients certificates
     *
     * @param {CertificateCollection} certs
     *
     * @memberOf Cipher
     */
    set recipientsCerts(certs: CertificateCollection) {
        this.handle.addRecipientsCerts(certs.handle);
    }

    /**
     * Set private key
     *
     * @param {Key} key
     *
     * @memberOf Cipher
     */
    set privKey(rkey: Key) {
        this.handle.setPrivKey(rkey.handle);
    }

    /**
     * Set recipient certificate
     *
     * @param {Certificate} rcert
     *
     * @memberOf Cipher
     */
    set recipientCert(rcert: Certificate) {
        this.handle.setRecipientCert(rcert.handle);
    }

    set password(pass: string) {
        this.handle.setPass(pass);
    }

    set digest(digest: string) {
        this.handle.setDigest(digest);
    }

    get riv(): Buffer {
        return this.handle.getIV();
    }

    set iv(iv: string) {
        this.handle.setIV(iv);
    }

    get rkey(): Buffer {
        return this.handle.getKey();
    }

    set key(key: string) {
        this.handle.setKey(key);
    }

    get rsalt(): Buffer {
        return this.handle.getSalt();
    }

    set salt(salt: string) {
        this.handle.setSalt(salt);
    }

    get algorithm(): String {
        return this.handle.getAlgorithm();
    }

    get mode(): String {
        return this.handle.getMode();
    }

    get dgst(): String {
        return this.handle.getDigestAlgorithm();
    }

    /**
     * Return recipient infos
     *
     * @param {string} filenameEnc File path
     * @param {DataFormat} format DataFormat.PEM | DataFormat.DER
     * @returns {CmsRecipientInfoCollection}
     *
     * @memberOf Cipher
     */
    public getRecipientInfos(filenameEnc: string, format: DataFormat): CmsRecipientInfoCollection {
        return CmsRecipientInfoCollection.wrap<native.CMS.CmsRecipientInfoCollection, CmsRecipientInfoCollection>
            (this.handle.getRecipientInfos(filenameEnc, format));
    }
}
