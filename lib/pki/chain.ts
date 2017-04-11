/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Chain of certificates
     *
     * @export
     * @class Chain
     * @extends {BaseObject<native.PKI.Chain>}
     */
    export class Chain extends BaseObject<native.PKI.Chain> {

        /**
         * Creates an instance of Chain.
         *
         *
         * @memberOf Chain
         */
        constructor() {
            super();
            this.handle = new native.PKI.Chain();
        }

        /**
         * Build chain
         *
         * @param {Certificate} cert Last certificate in chain
         * @param {CertificateCollection} certs All certificates where search issuer certificates
         * @returns {CertificateCollection}
         *
         * @memberOf Chain
         */
        public buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection {
            const certscol: CertificateCollection =
                new CertificateCollection(this.handle.buildChain(cert.handle, certs.handle));
            return certscol;
        }

        /**
         * Verify chain (crl collection if need check revocation)
         *
         * @param {CertificateCollection} chain Certificates collection
         * @param {CrlCollection} crls Crl collection
         * @returns {boolean}
         *
         * @memberOf Chain
         */
        public verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean {
            let crlsD: CrlCollection = crls;
            if (!crls) {
                crlsD = new CrlCollection();
            }
            return this.handle.verifyChain(chain.handle, crlsD.handle);
        }
    }
}
