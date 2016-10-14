import * as native from "../native";
import * as object from "../object";
import {Key} from "./key";

/**
 * Wrap X509_REQ_INFO
 *
 * @export
 * @class CertificationRequestInfo
 * @extends {object.BaseObject<native.PKI.CertificationRequestInfo>}
 */
export class CertificationRequestInfo extends object.BaseObject<native.PKI.CertificationRequestInfo> {

    /**
     * Creates an instance of CertificationRequestInfo.
     *
     *
     * @memberOf CertificationRequestInfo
     */
    constructor();

    /**
     * Creates an instance of CertificationRequestInfo.
     *
     * @param {native.PKI.CertificationRequestInfo} handle
     *
     * @memberOf CertificationRequestInfo
     */
    constructor(handle: native.PKI.CertificationRequestInfo);

    /**
     * Creates an instance of CertificationRequestInfo.
     *
     * @param {*} [param]
     *
     * @memberOf CertificationRequestInfo
     */
    constructor(param?: any) {
        super();

        if (param instanceof native.PKI.CertificationRequestInfo) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.CertificationRequestInfo();
        }
    }

    /**
     * Set subject name
     *
     * @param {string} x509name Example "/C=US/O=Test/CN=example.com"
     *
     * @memberOf CertificationRequestInfo
     */
    set subject(x509name: string) {
        this.handle.setSubject(x509name);
    }

    /**
     *  Set public key
     *
     *  @param {Key} pubkey Public key
     *
     * @memberOf CertificationRequestInfo
     */
    set pubkey(pubkey: Key) {
        this.handle.setSubjectPublicKey(pubkey.handle);
    }

    /**
     * Set version certificate
     *
     * @param {number} version
     *
     * @memberOf CertificationRequestInfo
     */
    set version(version: number) {
        this.handle.setVersion(version);
    }

}
