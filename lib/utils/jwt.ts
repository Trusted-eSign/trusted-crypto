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
        public static ckeckLicense(): boolean {
            let jwt = new native.UTILS.Jwt();
            return jwt.checkLicense();
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
        };

        /**
         * Verify jwt license file
         *
         * @returns {boolean}
         *
         * @memberOf Jwt
         */
        public ckeckLicense(): boolean {
            return this.handle.checkLicense();
        }
    }
}
