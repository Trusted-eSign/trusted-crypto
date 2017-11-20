/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
/* tslint:disable:no-bitwise */

namespace trusted.cms {

    const DEFAULT_DATA_FORMAT: DataFormat = DataFormat.DER;

    export enum SignedDataContentType {
        url,
        buffer,
    }

    export interface ISignedDataContent {
        type: SignedDataContentType;
        data: string | Buffer;
    }

    /**
     * Signed data policy
     *
     * @enum {number}
     */
    enum SignedDataPolicy {
        text = 0x1,
        noCertificates = 0x2,
        noContentVerify = 0x4,
        noAttributeVerify = 0x8,
        noSignatures = noAttributeVerify | noContentVerify,
        noIntern = 0x10,
        noSignerCertificateVerify = 0x20,
        noVerify = 0x20,
        detached = 0x40,
        binary = 0x80,
        noAttributes = 0x100,
        noSmimeCap = 0x200,
        noOldMimeType = 0x400,
        crlFEOL = 0x800,
        stream = 0x1000,
        noCrtl = 0x2000,
        partial = 0x4000,
        reuseDigest = 0x8000,
        useKeyId = 0x10000,
        debugDecrypt = 0x20000,
    }

    /**
     * Get name
     *
     * @param {*} e
     * @param {string} name
     * @returns {*}
     */
    function EnumGetName(e: any, name: string): any {
        "use strict";

        for (const i in e) {
            if (i.toString().toLowerCase() === name.toLowerCase()) {
                return { name: i, value: e[i] };
            }
        }
        return undefined;
    }

    /**
     * Wrap CMS_ContentInfo
     *
     * @export
     * @class SignedData
     * @extends {BaseObject<native.CMS.SignedData>}
     */
    export class SignedData extends BaseObject<native.CMS.SignedData> {
        /**
         * Load signed data from file location
         *
         * @static
         * @param {string} filename File location
         * @param {DataFormat} [format] PEM | DER (default)
         * @returns {SignedData}
         *
         * @memberOf SignedData
         */
        public static load(filename: string, format?: DataFormat): SignedData {
            const cms: SignedData = new SignedData();
            cms.handle.load(filename, format);
            return cms;
        }

        /**
         * Load signed data from memory
         *
         * @static
         * @param {Buffer} buffer
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
         * @returns {SignedData}
         *
         * @memberOf SignedData
         */
        public static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): SignedData {
            const cms: SignedData = new SignedData();
            cms.handle.import(buffer, format);
            return cms;
        }

        private prContent: ISignedDataContent = undefined;

        /**
         * Creates an instance of SignedData.
         *
         *
         * @memberOf SignedData
         */
        constructor() {
            super();

            this.handle = new native.CMS.SignedData();
        }

        /**
         * Return content of signed data
         *
         * @type {ISignedDataContent}
         * @memberOf SignedData
         */
        get content(): ISignedDataContent {
            if (!this.prContent && !this.isDetached()) {
                // Извлечь содержимое из подписи
                const buf: Buffer = this.handle.getContent();
                this.prContent = {
                    data: buf,
                    type: SignedDataContentType.buffer,
                };
            }
            return this.prContent;
        }

        /**
         * Set content v to signed data
         *
         *
         * @memberOf SignedData
         */
        set content(v: ISignedDataContent) {
            let data: any;
            if (v.type === SignedDataContentType.url) {
                data = v.data.toString();
            } else {
                data = new Buffer(v.data as any);
            }
            this.handle.setContent(data);
            this.prContent = v;
        }

        /**
         * Return sign policys
         *
         * @type {Array<string>}
         * @memberOf SignedData
         */
        get policies(): string[] {
            const p: string[] = new Array<string>();

            const flags: number = this.handle.getFlags();

            for (const i in SignedDataPolicy) {
                if (+i & flags) {
                    p.push(SignedDataPolicy[i]);
                }
            }

            return p;
        }

        /**
         * Set sign policies
         *
         *
         * @memberOf SignedData
         */
        set policies(v: string[]) {
            let flags: number = 0;
            for (const item of v) {
                const flag: any = EnumGetName(SignedDataPolicy, item);
                if (flag) {
                    flags |= +flag.value;
                }
            }

            this.handle.setFlags(flags);
        }

        /**
         * Return true if sign detached
         *
         * @returns {boolean}
         *
         * @memberOf SignedData
         */
        public isDetached(): boolean {
            return this.handle.isDetached();
        }

        /**
         * Return certificate by index
         *
         * @param {number} index
         * @returns {Certificate}
         *
         * @memberOf SignedData
         */
        public certificates(index: number): pki.Certificate;

        /**
         * Return certificates collection
         *
         * @returns {CertificateCollection}
         *
         * @memberOf SignedData
         */
        public certificates(): pki.CertificateCollection;

        /**
         * Return certificates collection or certificate by index (if request)
         *
         * @param {number} [index]
         * @returns {*}
         *
         * @memberOf SignedData
         */
        public certificates(index?: number): any {
            const certs: pki.CertificateCollection = new pki.CertificateCollection(this.handle.getCertificates());
            if (index !== undefined) {
                return certs.items(index);
            }
            return certs;
        }

        /**
         * Return signer by index
         *
         * @param {number} index
         * @returns {Signer}
         *
         * @memberOf SignedData
         */
        public signers(index: number): Signer;

        /**
         * Return signers collection
         *
         * @returns {SignerCollection}
         *
         * @memberOf SignedData
         */
        public signers(): SignerCollection;

        /**
         * Return signers collection or signer by index (if request)
         *
         * @param {number} [index]
         * @returns {*}
         *
         * @memberOf SignedData
         */
        public signers(index?: number): any {
            const signers: SignerCollection = new SignerCollection(this.handle.getSigners());
            if (index !== undefined) {
                return signers.items(index);
            }
            return signers;
        }

        /**
         * Load sign from file location
         *
         * @param {string} filename File location
         * @param {DataFormat} [format] PEM | DER
         *
         * @memberOf SignedData
         */
        public load(filename: string, format?: DataFormat): void {
            this.handle.load(filename, format);
        }

        /**
         * Load sign from memory
         *
         * @param {Buffer} buffer
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         *
         * @memberOf SignedData
         */
        public import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.import(buffer, format);
        }

        /**
         * Save sign to memory
         *
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         * @returns {Buffer}
         *
         * @memberOf SignedData
         */
        public export(format: DataFormat = DEFAULT_DATA_FORMAT): Buffer {
            return this.handle.export(format);
        }

        /**
         * Write sign to file
         *
         * @param {string} filename File location
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         *
         * @memberOf SignedData
         */
        public save(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.save(filename, format);
        }

        /**
         * Create new signer
         *
         * @param {Certificate} cert Signer certificate
         * @param {Key} key Private key for signer certificate
         * @returns {Signer}
         *
         * @memberOf SignedData
         */
        public createSigner(cert: pki.Certificate, key: pki.Key): Signer {
            const signer: any = this.handle.createSigner(cert.handle, key.handle);
            return new Signer(signer);
        }

        /**
         * Verify signature
         *
         * @param {CertificateCollection} [certs] Certificate collection
         * @returns {boolean}
         *
         * @memberOf SignedData
         */
        public verify(certs?: pki.CertificateCollection): boolean {
            let certsD: pki.CertificateCollection = certs;
            if (!certs) {
                certsD = new pki.CertificateCollection();
            }
            return this.handle.verify(certsD.handle);
        }

        /**
         * Create sign
         *
         *
         * @memberOf SignedData
         */
        public sign(): void {
            this.handle.sign();
        }
    }
}
