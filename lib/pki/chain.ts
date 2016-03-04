import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Certificate} from "../pki/cert";
import {CertificateCollection} from "../pki/certs";
import {ProviderSystem} from "../pki/provider_system";

const DEFAULT_DATA_FORMAT = DataFormat.PEM;

export class Chain extends object.BaseObject<native.PKI.Chain> {

    constructor() {
        handle: native.PKI.Chain;
        super();
        this.handle = new native.PKI.Chain();
    }

    /**
     * @param  {Certificate} cert 
     * @param  {CertificateCollection} certs
     * @returns CertificateCollection
     */
    buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection{
       let certscol: CertificateCollection = new CertificateCollection(this.handle.buildChain(cert.handle, certs.handle));
        return certscol;
    }

    /**
     * @param  {CertificateCollection} chain
     * @param  {ProviderSystem} prvSys
     * @returns boolean
     */
    verifyChain(chain: CertificateCollection, prvSys: ProviderSystem): boolean {
       return this.handle.verifyChain(chain.handle, prvSys.handle);
    }

}