import * as native from "../native";
import * as object from "../object";

import {Certificate} from "../pki/cert";
import {Key} from "../pki/key";

/**
 * Support Microsoft crypto provider (only windows platform)
 *
 * @export
 * @class ProviderMicrosoft
 * @extends {object.BaseObject<native.PKISTORE.ProviderMicrosoft>}
 */
export class ProviderMicrosoft extends object.BaseObject<native.PKISTORE.ProviderMicrosoft> {
    /**
     * Creates an instance of ProviderMicrosoft.
     *
     *
     * @memberOf ProviderMicrosoft
     */
    constructor() {
        super();
        this.handle = new native.PKISTORE.ProviderMicrosoft();
    }

    /**
     * Return private key by certificate
     *
     * @param {Certificate} cert
     * @returns
     *
     * @memberOf ProviderMicrosoft
     */
    public getKey(cert: Certificate) {
         return Key.wrap<native.PKI.Key, Key>(this.handle.getKey(cert.handle));
    }
}
