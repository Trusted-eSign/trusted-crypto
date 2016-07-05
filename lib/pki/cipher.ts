import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {CryptoMethod} from "../crypto_method";
import {Key} from "./key";
import {CertificateCollection} from "./certs";
import {Certificate} from "./cert";

export class Cipher extends object.BaseObject<native.PKI.Cipher> {

    constructor(cipherName: string) {
        super();
        this.handle = new native.PKI.Cipher(cipherName);
    }

    /**
     * set crypto method
     * @param method SYMMETRIC or ASSIMETRIC
     */
    set cryptoMethod(method: CryptoMethod){
        this.handle.setCryptoMethod(method);
    }

    /**
     * encrypt data
     * @param filenameSource This file will encrypted
     * @param filenameEnc File for save encrypted data
     */
    public encrypt(filenameSource: string, filenameEnc: string, format?: DataFormat): void {
        this.handle.encrypt(filenameSource, filenameEnc, format);
    }

    /**
     * decrypt data
     * @param filenameEnc This file will decrypt
     * @param filenameDec File for save decrypted data
     */
    public decrypt(filenameEnc: string, filenameDec: string, format?: DataFormat): void {
        this.handle.decrypt(filenameEnc, filenameDec, format);
    }

    set recipientsCerts(certs: CertificateCollection){
        this.handle.addRecipientsCerts(certs.handle);
    }

    set privKey(rkey: Key){
        this.handle.setPrivKey(rkey.handle);
    }

    set recipientCert(rcert: Certificate){
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
}
