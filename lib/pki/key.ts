/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Wrap EVP_PKEY
     *
     * @export
     * @class Key
     * @extends {BaseObject<native.PKI.Key>}
     */
    export class Key extends BaseObject<native.PKI.Key> {
        /**
         * Load private key from file
         *
         * @static
         * @param {string} filename File path
         * @param {DataFormat} format PEM | DER
         * @param {string} password
         * @returns {Key}
         *
         * @memberOf Key
         */
        public static readPrivateKey(filename: string, format: DataFormat, password: string): Key {
            const key: Key = new Key();
            key.readPrivateKey.apply(key, arguments);
            return Key.wrap<native.PKI.Key, Key>(key.handle);
        }

        /**
         * Load public key from file
         *
         * @static
         * @param {string} filename File path
         * @param {DataFormat} format PEM | DER
         * @returns {Key}
         *
         * @memberOf Key
         */
        public static readPublicKey(filename: string, format: DataFormat): Key {
            const key: Key = new Key();
            key.readPublicKey.apply(key, arguments);
            return Key.wrap<native.PKI.Key, Key>(key.handle);
        }

        /**
         * Creates an instance of Key.
         * @param {native.PKI.Key} [param]
         *
         * @memberOf Key
         */
        constructor(param?: native.PKI.Key) {
            super();
            if (param instanceof native.PKI.Key) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.Key();
            }
        }

        /**
         * Generate key
         *
         * @param {string} algorithm
         * @param {string[]} [pkeyopts]
         * @returns {Key}
         * @memberof Key
         */
        public generate(algorithm: string, pkeyopts?: string[]): Key {
            return Key.wrap<native.PKI.Key, Key>(this.handle.generate(algorithm, pkeyopts));
        }

        /**
         * Load private key from file
         *
         * @param {string} filename File path
         * @param {DataFormat} format PEM | DER
         * @param {string} password
         * @returns {Key}
         *
         * @memberOf Key
         */
        public readPrivateKey(filename: string, format: DataFormat, password: string): Key {
            return Key.wrap<native.PKI.Key, Key>(this.handle.readPrivateKey(filename, format, password));
        }

        /**
         * Write private key to file
         *
         * @param {string} filename File path
         * @param {DataFormat} format PEM | DER
         * @param {string} password Set for encrypt
         * @returns {*}
         *
         * @memberOf Key
         */
        public writePrivateKey(filename: string, format: DataFormat, password: string): any {
            return this.handle.writePrivateKey(filename, format, password);
        }

        /**
         * Read public key from file
         *
         * @param {string} filename File path
         * @param {DataFormat} format PEM | DER
         * @returns {Key}
         *
         * @memberOf Key
         */
        public readPublicKey(filename: string, format: DataFormat): Key {
            return Key.wrap<native.PKI.Key, Key>(this.handle.readPublicKey(filename, format));
        }

        /**
         * Write public key to file
         *
         * @param {string} filename File path
         * @param {DataFormat} format PEM | DER
         * @returns {*}
         *
         * @memberOf Key
         */
        public writePublicKey(filename: string, format: DataFormat): any {
            return this.handle.writePublicKey(filename, format);
        }

        /**
         * Compare keys
         *
         * @param {Key} key Key for compare
         * @returns {number}
         *
         * @memberOf Key
         */
        public compare(key: Key): number {
            const cmp: number = this.handle.compare(key.handle);
            if (cmp < 0) {
                return -1;
            }
            if (cmp > 0) {
                return 1;
            }

            return 0;
        }
    }
}
