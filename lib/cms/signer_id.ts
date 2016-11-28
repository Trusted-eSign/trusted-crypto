/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.cms {
    /**
     * Wrap signer identifier information (keyidentifier, issuer name and serial number)
     *
     * @export
     * @class SignerId
     * @extends {BaseObject<native.CMS.SignerId>}
     */
    export class SignerId extends BaseObject<native.CMS.SignerId> {
        /**
         * Creates an instance of SignerId.
         *
         *
         * @memberOf SignerId
         */
        constructor(param?: any) {
            super();
            if (param instanceof native.CMS.SignerId) {
                this.handle = param;
            } else {
                this.handle = new native.CMS.SignerId();
            }
        }

        /**
         * Return full issuer name
         *
         * @readonly
         * @type {string}
         * @memberOf SignerId
         */
        get issuerName(): string {
            return this.handle.getIssuerName();
        }

        /**
         * Return serial number
         *
         * @readonly
         * @type {string}
         * @memberOf SignerId
         */
        get serialNumber(): string {
            return this.handle.getSerialNumber().toString();
        }

        /**
         * Return keyidentifier
         *
         * @readonly
         * @type {string}
         * @memberOf SignerId
         */
        get keyId(): string {
            return this.handle.getKeyId();
        }
    }
}
