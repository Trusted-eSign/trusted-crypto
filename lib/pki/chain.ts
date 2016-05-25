import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Certificate} from "../pki/cert";
import {CertificateCollection} from "../pki/certs";
import {PkiStore} from "../pkistore/pkistore";

const DEFAULT_DATA_FORMAT = DataFormat.PEM;

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

    /**
     * @param  {CertificateCollection} chain
     * @param  {PkiStore} store
     * @returns boolean
     */
    verifyChain(chain: CertificateCollection, store: PkiStore): boolean {
       return this.handle.verifyChain(chain.handle, store.handle);
    }
}
