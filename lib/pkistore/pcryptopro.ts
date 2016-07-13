import * as native from "../native";
import * as object from "../object";

export class ProviderCryptopro extends object.BaseObject<native.PKISTORE.ProviderCryptopro> {
    constructor() {
        super();
        this.handle = new native.PKISTORE.ProviderCryptopro();
    }
}
