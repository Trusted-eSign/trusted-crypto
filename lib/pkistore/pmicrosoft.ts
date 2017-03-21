/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pkistore {

    /**
     * Support Microsoft crypto provider (only windows platform)
     *
     * @export
     * @class ProviderMicrosoft
     * @extends {BaseObject<native.PKISTORE.ProviderMicrosoft>}
     */
    export class ProviderMicrosoft extends BaseObject<native.PKISTORE.ProviderMicrosoft> {
        /**
         * Creates an instance of ProviderMicrosoft.
         *
         *
         * @memberOf ProviderMicrosoft
         */
        constructor() {
            super();
            this.handle = new native.PKISTORE.ProviderMicrosoft();
        }

        /**
         * Return private key by certificate
         *
         * @param {Certificate} cert
         * @returns
         *
         * @memberOf ProviderMicrosoft
         */
        public getKey(cert: pki.Certificate) {
            return pki.Key.wrap<native.PKI.Key, pki.Key>(this.handle.getKey(cert.handle));
        }

        /**
         * Ensure that the certificate's private key is available
         *
         * @param {Certificate} cert
         * @returns {boolean}
         *
         * @memberOf ProviderMicrosoft
         */
        public hasPrivateKey(cert: pki.Certificate): boolean {
            return this.handle.hasPrivateKey(cert.handle);
        }
    }
}
