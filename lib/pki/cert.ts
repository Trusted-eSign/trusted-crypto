/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    const DEFAULT_DATA_FORMAT: DataFormat = DataFormat.DER;

    /**
     * Wrap X509
     *
     * @export
     * @class Certificate
     * @extends {BaseObject<native.PKI.Certificate>}
     */
    export class Certificate extends BaseObject<native.PKI.Certificate> {
        /**
         * Load certificate from file
         *
         * @static
         * @param {string} filename File location
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         * @returns {Certificate}
         *
         * @memberOf Certificate
         */
        public static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
            let cert: Certificate = new Certificate();
            cert.handle.load(filename, format);
            return cert;
        }

        /**
         * Load certificate from memory
         *
         * @static
         * @param {Buffer} buffer
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         * @returns {Certificate}
         *
         * @memberOf Certificate
         */
        public static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
            let cert: Certificate = new Certificate();
            cert.handle.import(buffer, format);
            return cert;
        }

        /**
         * Creates an instance of Certificate.
         *
         *
         * @memberOf Certificate
         */
        constructor();

        /**
         * Creates an instance of Certificate.
         *
         * @param {native.PKI.Certificate} handle
         *
         * @memberOf Certificate
         */
        constructor(handle: native.PKI.Certificate);

        /**
         * Creates an instance of Certificate.
         *
         * @param {*} [param]
         *
         * @memberOf Certificate
         */
        constructor(param?: any) {
            super();
            if (param instanceof native.PKI.Certificate) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.Certificate();
            }
        }

        /**
         * Return version of certificate
         *
         * @readonly
         * @type {number}
         * @memberOf Certificate
         */
        get version(): number {
            return this.handle.getVersion();
        }

        /**
         * Return serial number of certificate
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get serialNumber(): string {
            return this.handle.getSerialNumber().toString();
        }

        /**
         * Return type of certificate
         *
         * @readonly
         * @type {number}
         * @memberOf Certificate
         */
        get type(): number {
            return this.handle.getType();
        }

        /**
         * Return KeyUsageFlags collection
         *
         * @readonly
         * @type {number}
         * @memberOf Certificate
         */
        get keyUsage(): number {
            return this.handle.getKeyUsage();
        }

        /**
         * Return CN from issuer name
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get issuerFriendlyName(): string {
            return this.handle.getIssuerFriendlyName();
        }

        /**
         * Return issuer name
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get issuerName(): string {
            return this.handle.getIssuerName();
        }

        /**
         * Return CN from subject name
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get subjectFriendlyName(): string {
            return this.handle.getSubjectFriendlyName();
        }

        /**
         * Return subject name
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get subjectName(): string {
            return this.handle.getSubjectName();
        }

        /**
         * Return Not Before date
         *
         * @readonly
         * @type {Date}
         * @memberOf Certificate
         */
        get notBefore(): Date {
            return new Date(this.handle.getNotBefore());
        }

        /**
         * Return Not After date
         *
         * @readonly
         * @type {Date}
         * @memberOf Certificate
         */
        get notAfter(): Date {
            return new Date(this.handle.getNotAfter());
        }

        /**
         * Return SHA-1 thumbprint
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get thumbprint(): string {
            return this.handle.getThumbprint().toString("hex");
        }

        /**
         * Return signature algorithm
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get signatureAlgorithm(): string {
            return this.handle.getSignatureAlgorithm();
        }

        /**
         * Return signature digest algorithm
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get signatureDigest(): string {
            return this.handle.getSignatureDigest();
        }

        /**
         * Return organization name
         *
         * @readonly
         * @type {string}
         * @memberOf Certificate
         */
        get organizationName(): string {
            return this.handle.getOrganizationName();
        }

        /**
         * Compare certificates
         *
         * @param {Certificate} cert Certificate for compare
         * @returns {number}
         *
         * @memberOf Certificate
         */
        public compare(cert: Certificate): number {
            let cmp: any = this.handle.compare(cert.handle);
            if (cmp < 0) {
                return -1;
            }
            if (cmp > 0) {
                return 1;
            }

            return 0;
        }

        /**
         * Compare certificates
         *
         * @param {Certificate} cert Certificate for compare
         * @returns {boolean}
         *
         * @memberOf Certificate
         */
        public equals(cert: Certificate): boolean {
            return this.handle.equals(cert.handle);
        }

        /**
         * Return certificate hash
         *
         * @param {string} [algorithm="sha1"]
         * @returns {String}
         *
         * @memberOf Certificate
         */
        public hash(algorithm: string = "sha1"): String {
            return this.handle.hash(algorithm).toString("hex");
        }

        /**
         * Return certificate duplicat
         *
         * @returns {Certificate}
         *
         * @memberOf Certificate
         */
        public duplicate(): Certificate {
            let cert: Certificate = new Certificate();
            cert.handle = this.handle.duplicate();
            return cert;
        }

        /**
         * Load certificate from file location
         *
         * @param {string} filename File location
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
         *
         * @memberOf Certificate
         */
        public load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.load(filename, format);
        }

        /**
         * Load certificate from memory
         *
         * @param {Buffer} buffer
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
         *
         * @memberOf Certificate
         */
        public import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.import(buffer, format);
        }

        /**
         * Save certificate to memory
         *
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
         * @returns {Buffer}
         *
         * @memberOf Certificate
         */
        public export(format: DataFormat = DEFAULT_DATA_FORMAT): Buffer {
            return this.handle.export(format);
        }

        /**
         * Write certificate to file
         *
         * @param {string} filename File location
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         *
         * @memberOf Certificate
         */
        public save(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.save(filename, format);
        }
    }
}
