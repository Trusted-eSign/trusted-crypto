import * as native from "../native";
import * as object from "../object";
import {Certificate} from "../pki/cert";

export class CmsRecipientInfo extends object.BaseObject<native.CMS.CmsRecipientInfo> {
    constructor();
    constructor(handle: native.CMS.CmsRecipientInfo);
    constructor(param?: any) {
        super();
        if (param instanceof native.CMS.CmsRecipientInfo) {
            this.handle = param;
        } else {
            this.handle = new native.CMS.CmsRecipientInfo();
        }
    }

   /**
    * Return full issuer name
    */
    get issuerName(): string {
        return this.handle.getIssuerName();
    }

    /**
     * Return serial number
     */
    get serialNumber(): string {
        return this.handle.getSerialNumber().toString();
    }

    public ktriCertCmp(cert: Certificate): number {
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
