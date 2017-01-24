/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    const DEFAULT_DATA_FORMAT: DataFormat = DataFormat.DER;

    /**
     * Wrap X509_CRL
     *
     * @export
     * @class Crl
     * @extends {BaseObject<native.PKI.CRL>}
     */
    export class Crl extends BaseObject<native.PKI.CRL> {
        /**
         * Load CRL from File location
         *
         * @static
         * @param {string} filename File location
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         * @returns {Crl}
         *
         * @memberOf Crl
         */
        public static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): Crl {
            let crl: Crl = new Crl();
            crl.load(filename, format);
            return crl;
        }

        /**
         * Load CRL from memory
         *
         * @static
         * @param {Buffer} buffer
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
         * @returns {Crl}
         *
         * @memberOf Crl
         */
        public static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): Crl {
            let crl: Crl = new Crl();
            crl.import(buffer, format);
            return crl;
        }

        /**
         * Creates an instance of Crl.
         *
         *
         * @memberOf Crl
         */
        constructor();

        /**
         * Creates an instance of Crl.
         *
         * @param {native.PKI.CRL} handle
         *
         * @memberOf Crl
         */
        constructor(handle: native.PKI.CRL);

        /**
         * Creates an instance of Crl.
         *
         * @param {*} [param]
         *
         * @memberOf Crl
         */
        constructor(param?: any) {
            super();
            if (param instanceof native.PKI.CRL) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.CRL();
            }
        }

        /**
         * Return CRL in DER format
         *
         * @readonly
         * @type {Buffer}
         * @memberOf Crl
         */
        get encoded(): Buffer {
            return this.handle.getEncoded();
        }

        /**
         * Return signature
         *
         * @readonly
         * @type {Buffer}
         * @memberOf Crl
         */
        get signature(): Buffer {
            return this.handle.getSignature();
        }

        /**
         * Return version of CRL
         *
         * @readonly
         * @type {number}
         * @memberOf Crl
         */
        get version(): number {
            return this.handle.getVersion();
        }

        /**
         * Return issuer name
         *
         * @readonly
         * @type {string}
         * @memberOf Crl
         */
        get issuerName(): string {
            return this.handle.getIssuerName();
        }

        /**
         * Return CN from issuer name
         *
         * @readonly
         * @type {string}
         * @memberOf Crl
         */
        get issuerFriendlyName(): string {
            return this.handle.getIssuerFriendlyName();
        }

        /**
         * Return last update date
         *
         * @readonly
         * @type {Date}
         * @memberOf Crl
         */
        get lastUpdate(): Date {
            return new Date(this.handle.getLastUpdate());
        }

        /**
         * Return next update date
         *
         * @readonly
         * @type {Date}
         * @memberOf Crl
         */
        get nextUpdate(): Date {
            return new Date(this.handle.getNextUpdate());
        }

        /**
         * Return SHA-1 thumbprint
         *
         * @readonly
         * @type {string}
         * @memberOf Crl
         */
        get thumbprint(): string {
            return this.handle.getThumbprint().toString("hex");
        }

        /**
         * Return signature algorithm
         *
         * @readonly
         * @type {string}
         * @memberOf Crl
         */
        get sigAlgName(): string {
            return this.handle.getSigAlgName();
        }

        /**
         * Return signature short algorithm
         *
         * @readonly
         * @type {string}
         * @memberOf Crl
         */
        get sigAlgShortName(): string {
            return this.handle.getSigAlgShortName();
        }

        /**
         * Return signature algorithm OID
         *
         * @readonly
         * @type {string}
         * @memberOf Crl
         */
        get sigAlgOID(): string {
            return this.handle.getSigAlgOID();
        }

        /**
         * Return revoced collection
         *
         * @readonly
         * @type {native.PKI.RevokedCollection}
         * @memberOf Crl
         */
        get revoked(): RevokedCollection {
            return RevokedCollection.wrap<native.PKI.RevokedCollection, RevokedCollection>(this.handle.getRevoked());
        }

        /**
         * Load CRL from file
         *
         * @param {string} filename File location
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
         *
         * @memberOf Crl
         */
        public load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.load(filename, format);
        }

        /**
         * Load CRL from memory
         *
         * @param {Buffer} buffer
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
         *
         * @memberOf Crl
         */
        public import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.import(buffer, format);
        }

        /**
         * Save CRL to memory
         *
         * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
         * @returns {Buffer}
         *
         * @memberOf Crl
         */
        public export(format: DataFormat = DEFAULT_DATA_FORMAT): Buffer {
            return this.handle.export(format);
        }

        /**
         * Write CRL to file
         *
         * @param {string} filename File location
         * @param {DataFormat} [dataFormat=DEFAULT_DATA_FORMAT]
         *
         * @memberOf Crl
         */
        public save(filename: string, dataFormat: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.save(filename, dataFormat);
        }

        /**
         * Compare CRLs
         *
         * @param {Crl} crl CRL for compare
         * @returns {number}
         *
         * @memberOf Crl
         */
        public compare(crl: Crl): number {
            let cmp: number = this.handle.compare(crl.handle);
            if (cmp < 0) {
                return -1;
            }
            if (cmp > 0) {
                return 1;
            }

            return 0;
        }

        /**
         * Compare CRLs
         *
         * @param {Crl} crl CRL for compare
         * @returns {boolean}
         *
         * @memberOf Crl
         */
        public equals(crl: Crl): boolean {
            return this.handle.equals(crl.handle);
        }

        /**
         * Return CRL hash
         *
         * @param {string} [algorithm="sha1"]
         * @returns {String}
         *
         * @memberOf Crl
         */
        public hash(algorithm: string = "sha1"): String {
            return this.handle.hash(algorithm).toString("hex");
        }

        /**
         * Return CRL duplicat
         *
         * @returns {Crl}
         *
         * @memberOf Crl
         */
        public duplicate(): Crl {
            let crl: Crl = new Crl();
            crl.handle = this.handle.duplicate();
            return crl;
        }
    }
}
