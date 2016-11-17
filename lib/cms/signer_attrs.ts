/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.cms {
    /**
     * Collection of SignerAttribute
     *
     * @export
     * @class SignerAttributeCollection
     * @extends {BaseObject<native.CMS.SignerAttributeCollection>}
     * @implements {ICollection}
     */
    export class SignerAttributeCollection extends BaseObject<native.CMS.SignerAttributeCollection>
        implements core.ICollection {
        /**
         * Creates an instance of SignerAttributeCollection.
         *
         * @param {native.CMS.SignerAttributeCollection} nativeSigner
         *
         * @memberOf SignerAttributeCollection
         */
        constructor(nativeSigner: native.CMS.SignerAttributeCollection) {
            super();

            this.handle = nativeSigner;
        }

        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberOf SignerAttributeCollection
         */
        get length(): number {
            return this.handle.length();
        }

        /**
         * Add new element to collection
         *
         * @param {Attribute} attr
         *
         * @memberOf SignerAttributeCollection
         */
        public push(attr: pki.Attribute): void {
            this.handle.push(attr.handle);
        }

        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf SignerAttributeCollection
         */
        public removeAt(index: number): void {
            this.handle.removeAt(index);
        }

        /**
         *
         * @param {number} index
         * @returns {Attribute}
         *
         * @memberOf SignerAttributeCollection
         */
        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns
         *
         * @memberOf SignerAttributeCollection
         */
        public items(index: number) {
            return new pki.Attribute(this.handle.items(index));
        }
    }
}
