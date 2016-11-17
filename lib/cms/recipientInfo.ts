namespace trusted.cms {

    /**
     * Wrap CMS_RecipientInfo
     *
     * @export
     * @class CmsRecipientInfo
     * @extends {BaseObject<native.CMS.CmsRecipientInfo>}
     */
    export class CmsRecipientInfo extends BaseObject<native.CMS.CmsRecipientInfo> {
        /**
         * Creates an instance of CmsRecipientInfo.
         *
         *
         * @memberOf CmsRecipientInfo
         */
        constructor();

        /**
         * Creates an instance of CmsRecipientInfo.
         *
         * @param {native.CMS.CmsRecipientInfo} handle
         *
         * @memberOf CmsRecipientInfo
         */
        constructor(handle: native.CMS.CmsRecipientInfo);

        /**
         * Creates an instance of CmsRecipientInfo.
         *
         * @param {*} [param]
         *
         * @memberOf CmsRecipientInfo
         */
        constructor(param?: any) {
            super();
            if (param instanceof native.CMS.CmsRecipientInfo) {
                this.handle = param;
            } else {
                this.handle = new native.CMS.CmsRecipientInfo();
            }
        }

        /**
         *  Return full issuer name
         *
         * @readonly
         * @type {string}
         * @memberOf CmsRecipientInfo
         */
        get issuerName(): string {
            return this.handle.getIssuerName();
        }

        /**
         * Return serial number
         *
         * @readonly
         * @type {string}
         * @memberOf CmsRecipientInfo
         */
        get serialNumber(): string {
            return this.handle.getSerialNumber().toString();
        }

        /**
         * Compares the certificate cert against the CMS_RecipientInfo structure
         *
         * @param {Certificate} cert
         * @returns {number}
         *
         * @memberOf CmsRecipientInfo
         */
        public ktriCertCmp(cert: pki.Certificate): number {
            let cmp: any = this.handle.ktriCertCmp(cert.handle);
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