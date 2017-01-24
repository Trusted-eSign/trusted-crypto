/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Collection of Revoked
     *
     * @export
     * @class RevokedCollection
     * @extends {BaseObject<native.PKI.RevokedCollection>}
     * @implements {core.ICollectionWrite}
     */
    export class RevokedCollection extends BaseObject<native.PKI.RevokedCollection> implements core.ICollectionWrite {
        /**
         * Creates an instance of RevokedCollection.
         *
         * @param {native.PKI.RevokedCollection} handle
         *
         * @memberOf RevokedCollection
         */
        constructor(handle: native.PKI.RevokedCollection);

        /**
         * Creates an instance of RevokedCollection.
         *
         *
         * @memberOf RevokedCollection
         */
        constructor();

        /**
         * Creates an instance of RevokedCollection.
         *
         * @param {*} [param]
         *
         * @memberOf RevokedCollection
         */
        constructor(param?: any) {
            super();
            if (param instanceof native.PKI.RevokedCollection) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.RevokedCollection();
            }
        }

        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns {Revoked}
         *
         * @memberOf RevokedCollection
         */
        public items(index: number): Revoked {
            return Revoked.wrap<native.PKI.Revoked, Revoked>(this.handle.items(index));
        }

        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberOf RevokedCollection
         */
        get length(): number {
            return this.handle.length();
        }

        /**
         * Add new element to collection
         *
         * @param {Revoked} revoked
         *
         * @memberOf RevokedCollection
         */
        public push(rv: Revoked): void {
            this.handle.push(rv.handle);
        }

        /**
         * Remove last element from collection
         *
         *
         * @memberOf RevokedCollection
         */
        public pop(): void {
            this.handle.pop();
        }

        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf RevokedCollection
         */
        public removeAt(index: number): void {
            this.handle.removeAt(index);
        }
    }
}
