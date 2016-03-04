import * as native from "../native";
import * as object from "../object";

export class Provider_System extends object.BaseObject<native.PKI.Provider_System> {

    constructor(folder: string) {
        handle: native.PKI.Provider_System;
        super();
        this.handle = new native.PKI.Provider_System(folder);
    }

}