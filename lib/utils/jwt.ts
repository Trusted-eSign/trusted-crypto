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
    }
}
