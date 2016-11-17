/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Collection of Attribute
     *
     * @export
     * @class AttributeValueCollection
     * @extends {BaseObject<native.PKI.AttributeValueCollection>}
     * @implements {core.ICollectionWrite}
     */
    export class AttributeValueCollection extends BaseObject<native.PKI.AttributeValueCollection>
        implements core.ICollectionWrite {

        /**
         * Creates an instance of AttributeValueCollection.
         *
         * @param {native.PKI.AttributeValueCollection} handle
         *
         * @memberOf AttributeValueCollection
         */
        constructor(handle: native.PKI.AttributeValueCollection) {
            super();

            this.handle = handle;
        }

        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberOf AttributeValueCollection
         */
        get length(): number {
            return this.handle.length();
        }

        /**
         * Add new element to collection
         *
         * @param {Buffer} val
         *
         * @memberOf AttributeValueCollection
         */
        public push(val: Buffer): void {
            this.handle.push(val);
        }

        /**
         * Remove last element from collection
         *
         *
         * @memberOf AttributeValueCollection
         */
        public pop(): void {
            this.handle.pop();
        }

        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf AttributeValueCollection
         */
        public removeAt(index: number): void {
            this.handle.removeAt(index);
        }

        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns {Buffer}
         *
         * @memberOf AttributeValueCollection
         */
        public items(index: number): Buffer {
            return this.handle.items(index);
        }
    }
}
