/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pkistore {
    /**
     * Support CryptoPro provider
     *
     * @export
     * @class ProviderCryptopro
     * @extends {BaseObject<native.PKISTORE.ProviderCryptopro>}
     */
    export class ProviderCryptopro extends BaseObject<native.PKISTORE.ProviderCryptopro> {
        constructor() {
            super();
            this.handle = new native.PKISTORE.ProviderCryptopro();
        }

        /**
         * Return private key by certificate from CryptoPro store
         *
         * @param {Certificate} cert Certificate
         * @returns
         *
         * @memberOf ProviderCryptopro
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
         * @memberOf ProviderCryptopro
         */
        public hasPrivateKey(cert: pki.Certificate): boolean {
            return this.handle.hasPrivateKey(cert.handle);
        }
    }
}
