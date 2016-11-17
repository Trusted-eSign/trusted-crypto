/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.cms {
    /**
     * Collection of CmsRecipientInfo
     *
     * @export
     * @class CmsRecipientInfoCollection
     * @extends {BaseObject<native.CMS.CmsRecipientInfoCollection>}
     * @implements {core.ICollectionWrite}
     */
    export class CmsRecipientInfoCollection extends BaseObject<native.CMS.CmsRecipientInfoCollection>
        implements core.ICollectionWrite {
        /**
         * Creates an instance of CmsRecipientInfoCollection.
         *
         *
         * @memberOf CmsRecipientInfoCollection
         */
        constructor();

        /**
         * Creates an instance of CmsRecipientInfoCollection.
         *
         * @param {native.CMS.CmsRecipientInfoCollection} handle
         *
         * @memberOf CmsRecipientInfoCollection
         */
        constructor(handle: native.CMS.CmsRecipientInfoCollection);

        /**
         * Creates an instance of CmsRecipientInfoCollection.
         *
         * @param {*} [param]
         *
         * @memberOf CmsRecipientInfoCollection
         */
        constructor(param?: any) {
            super();
            if (param instanceof native.CMS.CmsRecipientInfoCollection) {
                this.handle = param;
            } else {
                this.handle = new native.CMS.CmsRecipientInfoCollection();
            }
        }

        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns {CmsRecipientInfo}
         *
         * @memberOf CmsRecipientInfoCollection
         */
        public items(index: number): CmsRecipientInfo {
            return CmsRecipientInfo.wrap<native.CMS.CmsRecipientInfo, CmsRecipientInfo>(this.handle.items(index));
        }

        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberOf CmsRecipientInfoCollection
         */
        get length(): number {
            return this.handle.length();
        }

        /**
         * Add new element to collection
         *
         * @param {CmsRecipientInfo} ri
         *
         * @memberOf CmsRecipientInfoCollection
         */
        public push(ri: CmsRecipientInfo): void {
            this.handle.push(ri.handle);
        }

        /**
         * Remove last element from collection
         *
         *
         * @memberOf CmsRecipientInfoCollection
         */
        public pop(): void {
            this.handle.pop();
        }

        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf CmsRecipientInfoCollection
         */
        public removeAt(index: number): void {
            this.handle.removeAt(index);
        }
    }
}
