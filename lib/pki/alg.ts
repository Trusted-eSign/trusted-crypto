/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Wrap X509_ALGOR
     *
     * @export
     * @class Algorithm
     * @extends {BaseObject<native.PKI.Algorithm>}
     */
    export class Algorithm extends BaseObject<native.PKI.Algorithm> {
        /**
         * Creates an instance of Algorithm.
         * @param {(native.PKI.Algorithm | string)} [param]
         *
         * @memberOf Algorithm
         */
        constructor(param?: native.PKI.Algorithm | string) {
            super();

            if (param instanceof native.PKI.Algorithm) {
                this.handle = param;
            } else if (param) {
                this.handle = new native.PKI.Algorithm(param);
            } else {
                this.handle = new native.PKI.Algorithm();
            }
        }

        /**
         * Return algorithm name
         *
         * @readonly
         * @type {string}
         * @memberOf Algorithm
         */
        get name(): string {
            return this.handle.getName();
        }

        /**
         * Return algorithm OID
         *
         * @readonly
         * @type {Oid}
         * @memberOf Algorithm
         */
        get typeId(): Oid {
            return new Oid(this.handle.getTypeId());
        }

        /**
         * Return algorithm duplicat
         *
         * @returns {Algorithm}
         *
         * @memberOf Algorithm
         */
        public duplicate(): Algorithm {
            const walg: any = this.handle.duplicate();
            const alg: any = new Algorithm();
            alg.handle = walg;
            return alg;
        }

        /**
         * Return true if it digest algorithm
         *
         * @returns {boolean}
         *
         * @memberOf Algorithm
         */
        public isDigest(): boolean {
            return this.handle.isDigest();
        }
    }

}
