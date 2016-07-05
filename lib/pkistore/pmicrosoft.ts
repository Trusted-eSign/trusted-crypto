import * as native from "../native";
import * as object from "../object";

export class ProviderMicrosoft extends object.BaseObject<native.PKISTORE.ProviderMicrosoft> {
    constructor() {
        super();
        this.handle = new native.PKISTORE.ProviderMicrosoft();
    }
}
