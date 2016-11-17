/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    const DEFAULT_DATA_FORMAT: DataFormat = DataFormat.PEM;

    /**
     * Final class for make certification request
     *
     * @export
     * @class CSR
     * @extends {BaseObject<native.PKI.CSR>}
     */
    export class CSR extends BaseObject<native.PKI.CSR> {
        /**
         * Creates an instance of CSR.
         *
         * @param {string} name
         * @param {Key} key
         * @param {string} digest
         *
         * @memberOf CSR
         */
        constructor(name: string, key: Key, digest: string) {
            super();
            this.handle = new native.PKI.CSR(name, key.handle, digest);
        }

        /**
         * Return encoded structure
         *
         * @readonly
         * @type {Buffer}
         * @memberOf CSR
         */
        get encoded(): Buffer {
            return this.handle.getEncodedHEX();
        }

        /**
         * Write CSR to file
         *
         * @param {string} filename File path
         * @param {DataFormat} [dataFormat=DEFAULT_DATA_FORMAT]
         *
         * @memberOf CSR
         */
        public save(filename: string, dataFormat: DataFormat = DEFAULT_DATA_FORMAT): void {
            this.handle.save(filename, dataFormat);
        }
    }
}
