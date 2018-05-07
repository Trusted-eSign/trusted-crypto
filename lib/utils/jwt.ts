/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.utils {
    /**
     * JSON Web Token (JWT)
     * Uses only with CTGOSTCP
     *
     * @export
     * @class Jwt
     * @extends {BaseObject<native.JWT.Jwt>}
     */
    export class Jwt extends BaseObject<native.UTILS.Jwt> {
        /**
         * Verify jwt license file
         * Return 0 if license correct
         *
         * @static
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public static checkLicense(data?: string): number {
            const jwt = new native.UTILS.Jwt();
            return (data ? jwt.checkLicense(data) : jwt.checkLicense());
        }

        /**
         * Verify jwt license file
         * Return 0 if license correct
         *
         * @static
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public static checkTrialLicense(): number {
            const jwt = new native.UTILS.Jwt();
            return jwt.checkTrialLicense();
        }

        /**
         * Get time Expiration
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public static getExpirationTime(data: string): number {
            const jwt = new native.UTILS.Jwt();
            return jwt.getExpirationTime(data);
        }
        /**
         * Get time Expiration
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public static getTrialExpirationTime(): number {
            const jwt = new native.UTILS.Jwt();
            return jwt.getTrialExpirationTime();
        }
        /**
         * Create Trial License
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public static createTrialLicense(): number {
            const jwt = new native.UTILS.Jwt();
            return jwt.createTrialLicense();
        }

        /**
         * Creates an instance of Jwt.
         *
         *
         * @memberOf Jwt
         */
        constructor() {
            super();
            this.handle = new native.UTILS.Jwt();
        }

        /**
         * Verify jwt license file
         * Return 0 if license correct
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public checkLicense(data?: string): number {
            return (data ? this.handle.checkLicense(data) : this.handle.checkLicense());
        }

        /**
         * Verify jwt license file
         * Return 0 if license correct
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public checkTrialLicense(): number {
            return this.handle.checkTrialLicense();
        }

        /**
         * Get time Expiration
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public getExpirationTime(data: string): number {
            return this.handle.getExpirationTime(data);
        }

        /**
         * Get time Expiration
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public getTrialExpirationTime(): number {
            return this.handle.getTrialExpirationTime();
        }

        /**
         * Create Trial License
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        public createTrialLicense(): number {
            return this.handle.createTrialLicense();
        }
    }
}
