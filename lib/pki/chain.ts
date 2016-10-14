import * as native from "../native";
import * as object from "../object";
import {Certificate} from "../pki/cert";
import {CertificateCollection} from "../pki/certs";
import {CrlCollection} from "../pki/crls";

/**
 * Chain of certificates
 *
 * @export
 * @class Chain
 * @extends {object.BaseObject<native.PKI.Chain>}
 */
export class Chain extends object.BaseObject<native.PKI.Chain> {

    /**
     * Creates an instance of Chain.
     *
     *
     * @memberOf Chain
     */
    constructor() {
        super();
        this.handle = new native.PKI.Chain();
    }

    /**
     * Build chain
     *
     * @param {Certificate} cert Last certificate in chain
     * @param {CertificateCollection} certs All certificates where search issuer certificates
     * @returns {CertificateCollection}
     *
     * @memberOf Chain
     */
    public buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection {
        let certscol: CertificateCollection =
         new CertificateCollection(this.handle.buildChain(cert.handle, certs.handle));
        return certscol;
    }

    /**
     * Verify chain (crl collection if need check revocation)
     *
     * @param {CertificateCollection} chain Certificates collection
     * @param {CrlCollection} crls Crl collection
     * @returns {boolean}
     *
     * @memberOf Chain
     */
    public verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean {
        let crlsD: CrlCollection  = crls;
        if (!crls) {
            crlsD = new CrlCollection();
        }
        return this.handle.verifyChain(chain.handle, crlsD.handle);
    }
}
