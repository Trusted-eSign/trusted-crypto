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
         *
         * @static
         * @returns {boolean}
         *
         * @memberOf Jwt
         */
        public static checkLicense(data?: string): boolean {
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
         *
         * @returns {boolean}
         *
         * @memberOf Jwt
         */
        public checkLicense(data?: string): boolean {
            return (data ? this.handle.checkLicense(data) : this.handle.checkLicense());
        }
    }
}
