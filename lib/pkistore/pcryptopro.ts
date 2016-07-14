import * as native from "../native";
import * as object from "../object";

import {Certificate} from "../pki/cert";
import {Key} from "../pki/key";

export class ProviderCryptopro extends object.BaseObject<native.PKISTORE.ProviderCryptopro> {
    constructor() {
        super();
        this.handle = new native.PKISTORE.ProviderCryptopro();
    }

    public getKey(cert: Certificate) {
         return Key.wrap<native.PKI.Key, Key>(this.handle.getKey(cert.handle));
    }
}
