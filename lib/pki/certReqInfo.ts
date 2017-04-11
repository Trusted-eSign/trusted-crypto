/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Wrap X509_REQ_INFO
     *
     * @export
     * @class CertificationRequestInfo
     * @extends {BaseObject<native.PKI.CertificationRequestInfo>}
     */
    export class CertificationRequestInfo extends BaseObject<native.PKI.CertificationRequestInfo> {

        /**
         * Creates an instance of CertificationRequestInfo.
         * @param {native.PKI.CertificationRequestInfo} [param]
         *
         * @memberOf CertificationRequestInfo
         */
        constructor(param?: native.PKI.CertificationRequestInfo) {
            super();

            if (param instanceof native.PKI.CertificationRequestInfo) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.CertificationRequestInfo();
            }
        }

        /**
         * Set subject name
         *
         * @param {string} x509name Example "/C=US/O=Test/CN=example.com"
         *
         * @memberOf CertificationRequestInfo
         */
        set subject(x509name: string) {
            this.handle.setSubject(x509name);
        }

        /**
         *  Set public key
         *
         *  @param {Key} pubkey Public key
         *
         * @memberOf CertificationRequestInfo
         */
        set pubkey(pubkey: Key) {
            this.handle.setSubjectPublicKey(pubkey.handle);
        }

        /**
         * Set version certificate
         *
         * @param {number} version
         *
         * @memberOf CertificationRequestInfo
         */
        set version(version: number) {
            this.handle.setVersion(version);
        }

    }
}
