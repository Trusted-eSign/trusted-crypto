import * as native from "../native";
import * as object from "../object";

export class Provider_System extends object.BaseObject<native.PKISTORE.Provider_System> {
    constructor(folder: string) {
        super();
        this.handle = new native.PKISTORE.Provider_System(folder);
    }
}