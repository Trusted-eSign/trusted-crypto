import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT = DataFormat.PEM;

export class Cipher extends object.BaseObject<native.PKI.Cipher> {
    
    constructor(cipherName: string) {       
        handle: native.PKI.Cipher;
        super();   
        this.handle = new native.PKI.Cipher(cipherName);
    }
    
    /**
     * encrypt data
     * @param filenameSource This file will encrypted
     * @param filenameEnc File for save encrypted data
     */
    encrypt(filenameSource: string, filenameEnc: string) {
        this.handle.encrypt(filenameSource, filenameEnc);
    }
    
    /**
     * decrypt data
     * @param filenameEnc This file will decrypt
     * @param filenameDec File for save decrypted data
     */    
    decrypt(filenameEnc: string, filenameDec: string) {
        this.handle.decrypt(filenameEnc, filenameDec);
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