/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Collection of Crl
     *
     * @export
     * @class CrlCollection
     * @extends {BaseObject<native.PKI.CrlCollection>}
     * @implements {core.ICollectionWrite}
     */
    export class CrlCollection extends BaseObject<native.PKI.CrlCollection> implements core.ICollectionWrite {

        /**
         * Creates an instance of CrlCollection.
         * @param {native.PKI.CrlCollection} [param]
         *
         * @memberOf CrlCollection
         */
        constructor(param?: native.PKI.CrlCollection) {
            super();
            if (param instanceof native.PKI.CrlCollection) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.CrlCollection();
            }
        }

        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns {Crl}
         *
         * @memberOf CrlCollection
         */
        public items(index: number): Crl {
            return Crl.wrap<native.PKI.CRL, Crl>(this.handle.items(index));
        }

        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberOf CrlCollection
         */
        get length(): number {
            return this.handle.length();
        }

        /**
         * Add new element to collection
         *
         * @param {Crl} crl
         *
         * @memberOf CrlCollection
         */
        public push(crl: Crl): void {
            this.handle.push(crl.handle);
        }

        /**
         * Remove last element from collection
         *
         *
         * @memberOf CrlCollection
         */
        public pop(): void {
            this.handle.pop();
        }

        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf CrlCollection
         */
        public removeAt(index: number): void {
            this.handle.removeAt(index);
        }
    }
}
