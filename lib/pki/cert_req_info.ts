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
         * Rerutn subject name
         *
         * @readonly
         * @type {string}
         * @memberof CertificationRequestInfo
         */
        get subject(): string {
            return this.handle.getSubject();
        }

        /**
         * Sets the subject of this certification request.
         *
         * @param {string} x509name Example "/C=US/O=Test/CN=example.com"
         *
         * @memberOf CertificationRequestInfo
         */
        set subject(x509name: string) {
            this.handle.setSubject(x509name);
        }

        /**
         * Rerutn subject public key
         *
         * @readonly
         * @type {Key}
         * @memberof CertificationRequestInfo
         */
        get publicKey(): Key {
            return Key.wrap<native.PKI.Key, Key>(this.handle.getPublicKey());
        }

        /**
         *  Set public key
         *
         *  @param {Key} pubkey Public key
         *
         * @memberOf CertificationRequestInfo
         */
        set publicKey(pubkey: pki.Key) {
            this.handle.setPublicKey(pubkey.handle);
        }

        /**
         * Rerutn version
         *
         * @readonly
         * @type {number}
         * @memberof CertificationRequestInfo
         */
        get version(): number {
            return this.handle.getVersion();
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
