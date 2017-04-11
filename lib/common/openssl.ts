/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.common {
    /**
     * OpenSSL helper class
     *
     * @export
     * @class OpenSSL
     * @extends {BaseObject<native.COMMON.OpenSSL>}
     */
    export class OpenSSL extends BaseObject<native.COMMON.OpenSSL> {
        /**
         * Load engines and add algorithms
         *
         * @static
         * @returns {void}
         *
         * @memberOf OpenSSL
         */
        public static run(): void {
            const openssl = new native.COMMON.OpenSSL();
            return openssl.run();
        }

        /**
         * Cleanup openssl objects and free errors
         *
         * @static
         * @returns {void}
         *
         * @memberOf OpenSSL
         */
        public static stop(): void {
            const openssl = new native.COMMON.OpenSSL();
            return openssl.stop();
        }

        /**
         * Print OpenSSL error stack
         *
         * @static
         * @returns {string}
         *
         * @memberOf OpenSSL
         */
        public static printErrors(): string {
            const openssl = new native.COMMON.OpenSSL();
            return openssl.printErrors();
        }

        /**
         * Creates an instance of OpenSSL.
         *
         *
         * @memberOf OpenSSL
         */
        constructor() {
            super();
            this.handle = new native.COMMON.OpenSSL();
        }
    }
}
