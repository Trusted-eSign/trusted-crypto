import * as native from "../native";
import * as object from "../object";

/* tslint:disable-next-line:class-name */
export class Provider_System extends object.BaseObject<native.PKISTORE.Provider_System> {
    constructor(folder: string) {
        super();
        this.handle = new native.PKISTORE.Provider_System(folder);
    }

    public objectToPkiItem(path: string): native.PKISTORE.IPkiItem {
        return this.handle.objectToPkiItem(path);
    }
}
