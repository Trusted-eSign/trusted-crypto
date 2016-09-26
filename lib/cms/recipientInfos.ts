import * as native from "../native";
import * as object from "../object";
import * as Collection from "../core/collection";
import {CmsRecipientInfo} from "./recipientInfo";

export class CmsRecipientInfoCollection extends object.BaseObject<native.CMS.CmsRecipientInfoCollection>
 implements Collection.ICollectionWrite {
    constructor(handle: native.CMS.CmsRecipientInfoCollection);
    constructor();
    constructor(param?: any) {
        super();
        if (param instanceof native.CMS.CmsRecipientInfoCollection) {
            this.handle = param;
        } else {
            this.handle = new native.CMS.CmsRecipientInfoCollection();
        }
    }

    public items(index: number): CmsRecipientInfo {
        return  CmsRecipientInfo.wrap<native.CMS.CmsRecipientInfo, CmsRecipientInfo>(this.handle.items(index));
    }

    get length(): number {
        return this.handle.length();
    }

    public push(ri: CmsRecipientInfo): void {
        this.handle.push(ri.handle);
    }

    public pop(): void {
        this.handle.pop();
    }

    public removeAt(index: number): void {
        this.handle.removeAt(index);
    }
}
