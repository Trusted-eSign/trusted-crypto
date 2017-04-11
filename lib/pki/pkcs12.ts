/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * PKCS#12 (PFX)
     *
     * @export
     * @class Pkcs12
     * @extends {BaseObject<native.PKI.Pkcs12>}
     */
    export class Pkcs12 extends BaseObject<native.PKI.Pkcs12> {
        /**
         * Load pkcs12 from file
         *
         * @static
         * @param {string} filename File location
         * @returns {Pkcs12}
         *
         * @memberOf Pkcs12
         */
        public static load(filename: string): Pkcs12 {
            const p12: Pkcs12 = new Pkcs12();
            p12.handle.load(filename);
            return p12;
        }

        /**
         * Creates an instance of Pkcs12.
         * @param {native.PKI.Pkcs12} [param]
         *
         * @memberOf Pkcs12
         */
        constructor(param?: native.PKI.Pkcs12) {
            super();
            if (param instanceof native.PKI.Pkcs12) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.Pkcs12();
            }
        }

        /**
         * Return certificate
         *
         * @param {string} password
         * @returns {Certificate}
         *
         * @memberOf Pkcs12
         */
        public certificate(password: string): Certificate {
            return Certificate.wrap<native.PKI.Certificate, Certificate>(this.handle.getCertificate(password));
        }

        /**
         * Return private key
         *
         * @param {string} password
         * @returns {Key}
         *
         * @memberOf Pkcs12
         */
        public key(password: string): Key {
            return Key.wrap<native.PKI.Key, Key>(this.handle.getKey(password));
        }

        /**
         * Return CA certificates (not client certificates)
         *
         * @param {string} password
         * @returns {CertificateCollection}
         *
         * @memberOf Pkcs12
         */
        public ca(password: string): CertificateCollection {
            const caCerts: CertificateCollection = new CertificateCollection(this.handle.getCACertificates(password));
            return caCerts;
        }

        /**
         * Load pkcs12 from file
         *
         * @param {string} filename File location
         *
         * @memberOf Pkcs12
         */
        public load(filename: string): void {
            this.handle.load(filename);
        }

        /**
         * Write pkcs12 to file
         *
         * @param {string} filename File location
         *
         * @memberOf Pkcs12
         */
        public save(filename: string): void {
            this.handle.save(filename);
        }

        /**
         * Create PKCS12 structure
         *
         * @param {Certificate} cert
         * @param {Key} key Private key
         * @param {CertificateCollection} ca
         * @param {string} password
         * @param {string} name Friendly name
         * @returns {Pkcs12}
         *
         * @memberOf Pkcs12
         */
        public create(cert: Certificate, key: Key, ca: CertificateCollection, password: string, name: string): Pkcs12 {
            const p12: Pkcs12 = new Pkcs12();
            p12.handle = this.handle.create(cert.handle, key.handle, ca ? ca.handle : undefined, password, name);
            return p12;
        }
    }
}
