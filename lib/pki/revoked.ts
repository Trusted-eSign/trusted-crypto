/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Wrap X509_REVOKED
     *
     * @export
     * @class Revoked
     * @extends {BaseObject<native.PKI.Revoked>}
     */
    export class Revoked extends BaseObject<native.PKI.Revoked> {
        /**
         * Creates an instance of Revoked.
         * @param {native.PKI.Revoked} [param]
         *
         * @memberOf Revoked
         */
        constructor(param?: native.PKI.Revoked) {
            super();
            if (param instanceof native.PKI.Revoked) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.Revoked();
            }
        }

        /**
         * Return serial nuber
         *
         * @readonly
         * @type {string}
         * @memberOf Revoked
         */
        get serialNumber(): string {
            return this.handle.getSerialNumber().toString();
        }

        /**
         * Return revocation date
         *
         * @readonly
         * @type {string}
         * @memberOf Revoked
         */
        get revocationDate(): string {
            return this.handle.getRevocationDate();
        }

        /**
         * Return reason
         *
         * @readonly
         * @type {number}
         * @memberOf Revoked
         */
        get reason(): string {
            return this.handle.getReason();
        }

        /**
         * Return Revoked duplicat
         *
         * @returns {Revoked}
         *
         * @memberOf Revoked
         */
        public duplicate(): Revoked {
            const rv: Revoked = new Revoked();
            rv.handle = this.handle.duplicate();
            return rv;
        }
    }
}
