/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    export enum CipherContentType {
        url,
        buffer,
    }

    export interface ICipherContent {
        type: CipherContentType;
        data: string | Buffer;
    }
    /**
     * Encrypt and decrypt operations
     *
     * @export
     * @class Cipher
     * @extends {BaseObject<native.PKI.Cipher>}
     */
    export class Cipher extends BaseObject<native.PKI.Cipher> {

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
        set cryptoMethod(method: CryptoMethod) {
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
        public encrypt(source: ICipherContent, destinationEnc: ICipherContent, format: DataFormat): string {
            let sourceData: any;
            let destinationData: any;

            if (source.type === CipherContentType.url)
                sourceData = source.data.toString();  
            else 
                sourceData = new Buffer(source.data.valueOf() as any);              

            if (destinationEnc.type === CipherContentType.url)
                destinationData = destinationEnc.data.toString();
            else
                destinationData = new Buffer(destinationEnc.data.valueOf() as any);            

            return this.handle.encrypt(sourceData, destinationData, format);
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
        public decrypt(sourceEnc: ICipherContent, destinationDec: ICipherContent, format: DataFormat): string {
            let sourceData: any;
            let destinationData: any;
            if (sourceEnc.type === CipherContentType.url)
                sourceData = sourceEnc.data.toString();
            else 
                sourceData = new Buffer(sourceEnc.data.valueOf() as any);
            
            if (destinationDec.type === CipherContentType.url)
                destinationData = destinationDec.data.toString();
            else
                destinationData = new Buffer(destinationDec.data.valueOf() as any);
                
            return this.handle.decrypt(sourceData, destinationData, format);
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

        get algorithm(): string {
            return this.handle.getAlgorithm();
        }

        get mode(): string {
            return this.handle.getMode();
        }

        get dgst(): string {
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
        public getRecipientInfos(filenameEnc: string, format: DataFormat): cms.CmsRecipientInfoCollection {
            return cms.CmsRecipientInfoCollection.wrap
                <native.CMS.CmsRecipientInfoCollection, cms.CmsRecipientInfoCollection>
                    (this.handle.getRecipientInfos(filenameEnc, format));
        }
    }
}
