/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.utils {
    /**
     * cryptographic service provider (CSP) helper
     * Uses on WIN32 or with CPROCSP
     *
     * @export
     * @class Csp
     * @extends {BaseObject<native.UTILS.Csp>}
     */
    export class Csp extends BaseObject<native.UTILS.Csp> {
        /**
         * Check available provaider for GOST 2001
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static isGost2001CSPAvailable(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.isGost2001CSPAvailable();
        }

        /**
         * Check available provaider for GOST 2012-256
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static isGost2012_256CSPAvailable(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.isGost2012_256CSPAvailable();
        }

        /**
         * Check available provaider for GOST 2012-512
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static isGost2012_512CSPAvailable(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.isGost2012_512CSPAvailable();
        }

        /**
         * Verify license for CryptoPro CSP
         * Throw exception if provaider not available
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static checkCPCSPLicense(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.checkCPCSPLicense();
        }

        /**
         * Return instaled correct license for CryptoPro CSP
         * Throw exception if provaider not available
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static getCPCSPLicense(): string {
            const csp = new native.UTILS.Csp();
            return csp.getCPCSPLicense();
        }

        /**
         * Creates an instance of Csp.
         *
         *
         * @memberOf Csp
         */
        constructor() {
            super();
            this.handle = new native.UTILS.Csp();
        }
    }
}
