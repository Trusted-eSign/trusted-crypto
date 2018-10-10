/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pkistore {
    /**
     * Work with json files
     *
     * @export
     * @class CashJson
     * @extends {BaseObject<native.PKISTORE.CashJson>}
     */
    export class CashJson extends BaseObject<native.PKISTORE.CashJson> {
        /**
         * Creates an instance of CashJson.
         *
         * @param {string} fileName File path
         *
         * @memberOf CashJson
         */
        constructor(fileName: string) {
            super();
            this.handle = new native.PKISTORE.CashJson(fileName);
        }

        /**
         * Return PkiItems from json
         *
         * @returns {native.PKISTORE.IPkiItem[]}
         *
         * @memberOf CashJson
         */
        public export(): native.PKISTORE.IPkiItem[] {
            return this.handle.export();
        }

        /**
         * Import PkiItems to json
         *
         * @param {native.PKISTORE.IPkiItem[]} items
         *
         * @memberOf CashJson
         */
        public import(items: native.PKISTORE.IPkiItem[]): void {
            for (const item of items) {
                const pkiItem: PkiItem = new PkiItem();

                pkiItem.format = item.format;
                pkiItem.type = item.type;
                pkiItem.category = item.category;
                pkiItem.provider = item.provider;
                pkiItem.uri = item.uri;
                pkiItem.hash = item.hash.toLocaleLowerCase();
                if (item.subjectName) {
                    pkiItem.subjectName = item.subjectName;
                }
                if (item.subjectFriendlyName) {
                    pkiItem.subjectFriendlyName = item.subjectFriendlyName;
                }
                if (item.issuerName) {
                    pkiItem.issuerName = item.issuerName;
                }
                if (item.issuerFriendlyName) {
                    pkiItem.issuerFriendlyName = item.issuerFriendlyName;
                }
                if (item.serial) {
                    pkiItem.serial = item.serial;
                }
                if (item.notBefore) {
                    pkiItem.notBefore = item.notBefore;
                }
                if (item.notAfter) {
                    pkiItem.notAfter = item.notAfter;
                }
                if (item.lastUpdate) {
                    pkiItem.lastUpdate = item.lastUpdate;
                }
                if (item.nextUpdate) {
                    pkiItem.nextUpdate = item.nextUpdate;
                }
                if (item.authorityKeyid) {
                    pkiItem.authorityKeyid = item.authorityKeyid;
                }
                if (item.crlNumber) {
                    pkiItem.crlNumber = item.crlNumber;
                }
                if (item.key) {
                    pkiItem.key = item.key;
                }
                if (item.encrypted) {
                    pkiItem.keyEnc = item.encrypted;
                }
                if (item.organizationName) {
                    pkiItem.organizationName = item.organizationName;
                }
                if (item.signatureAlgorithm) {
                    pkiItem.signatureAlgorithm = item.signatureAlgorithm;
                }
                if (item.signatureDigestAlgorithm) {
                    pkiItem.signatureDigestAlgorithm = item.signatureDigestAlgorithm;
                }

                this.handle.import(pkiItem.handle);
            }
        }
    }
}
