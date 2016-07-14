import * as native from "../native";
import * as object from "../object";

import {Certificate} from "../pki/cert";
import {Key} from "../pki/key";

export class ProviderMicrosoft extends object.BaseObject<native.PKISTORE.ProviderMicrosoft> {
    constructor() {
        super();
        this.handle = new native.PKISTORE.ProviderMicrosoft();
    }

    public getKey(cert: Certificate) {
         return Key.wrap<native.PKI.Key, Key>(this.handle.getKey(cert.handle));
    }
}
