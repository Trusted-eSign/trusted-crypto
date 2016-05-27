import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Certificate} from "../pki/cert";
import {CertificateCollection} from "../pki/certs";
import {CrlCollection} from "../pki/crls";

export class Chain extends object.BaseObject<native.PKI.Chain> {

    constructor() {
        super();
        this.handle = new native.PKI.Chain();
    }

    /**
     * @param  {Certificate} cert 
     * @param  {CertificateCollection} certs
     * @returns CertificateCollection
     */
    buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection {
        let certscol: CertificateCollection = new CertificateCollection(this.handle.buildChain(cert.handle, certs.handle));
        return certscol;
    }

    verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean {
        return this.handle.verifyChain(chain.handle, crls.handle);
    }
}
