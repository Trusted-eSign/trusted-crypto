import * as native from "../native";
import * as object from "../object";
import {Key} from "./key";

export class CertificationRequestInfo extends object.BaseObject<native.PKI.CertificationRequestInfo> {

    constructor();
    constructor(handle: native.PKI.CertificationRequestInfo);
    constructor(param?: any) {
        super();

        if (param instanceof native.PKI.CertificationRequestInfo) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.CertificationRequestInfo();
        }
    }

    set subject(x509name: string) {
        this.handle.setSubject(x509name);
    }

    set pubkey(pubkey: Key) {
        this.handle.setSubjectPublicKey(pubkey.handle);
    }

    set version(version: number) {
        this.handle.setVersion(version);
    }

}
