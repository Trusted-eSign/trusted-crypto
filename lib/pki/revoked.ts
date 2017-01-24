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
         *
         *
         * @memberOf Revoked
         */
        constructor();

        /**
         * Creates an instance of Revoked.
         *
         * @param {native.PKI.Revoked} handle
         *
         * @memberOf Revoked
         */
        constructor(handle: native.PKI.Revoked);

        /**
         * Creates an instance of Revoked.
         *
         * @param {*} [param]
         *
         * @memberOf Revoked
         */
        constructor(param?: any) {
            super();
            if (param instanceof native.PKI.Revoked) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.Revoked();
            }
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
        get reason(): number {
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
            let rv: Revoked = new Revoked();
            rv.handle = this.handle.duplicate();
            return rv;
        }
    }
}
