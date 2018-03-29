/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {
    /**
     * Collection of Extension
     *
     * @export
     * @class ExtensionCollection
     * @extends {BaseObject<native.PKI.ExtensionCollection>}
     * @implements {core.ICollectionWrite}
     */
    export class ExtensionCollection extends BaseObject<native.PKI.ExtensionCollection>
        implements core.ICollectionWrite {

        /**
         * Creates an instance of ExtensionCollection.
         * @param {native.PKI.ExtensionCollection} [param]
         * @memberof ExtensionCollection
         */
        constructor(param?: native.PKI.ExtensionCollection) {
            super();
            if (param instanceof native.PKI.ExtensionCollection) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.ExtensionCollection();
            }
        }

        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns {Extension}
         * @memberof ExtensionCollection
         */
        public items(index: number): Extension {
            return Extension.wrap<native.PKI.Extension, Extension>(this.handle.items(index));
        }

        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberof ExtensionCollection
         */
        get length(): number {
            return this.handle.length();
        }

        /**
         * Add new element to collection
         *
         * @param {Extension} ext
         * @memberof ExtensionCollection
         */
        public push(ext: Extension): void {
            this.handle.push(ext.handle);
        }
        /**
         * Remove last element from collection
         *
         * @memberof ExtensionCollection
         */
        public pop(): void {
            this.handle.pop();
        }

        /**
         * Remove element by index from collection
         *
         * @param {number} index
         * @memberof ExtensionCollection
         */
        public removeAt(index: number): void {
            this.handle.removeAt(index);
        }
    }
}
