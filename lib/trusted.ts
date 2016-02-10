import * as dataFormat from "./data_format";
import * as publicExponent from "./public_exponent";
import * as cert from "./pki/cert";
import * as certs from "./pki/certs";
import * as crl from "./pki/crl";
import * as key from "./pki/key";
import * as certstore from "./pki/certstore"
import * as providersystem from "./pki/provider_system"
import * as oid from "./pki/oid";
import * as alg from "./pki/alg";
import * as certRegInfo from "./pki/certRegInfo";
import * as certReg from "./pki/certReg";
import * as csr from "./pki/csr";
import * as cipher from "./pki/cipher";

import * as signed_data from "./cms/signed_data";
import * as signer from "./cms/signer"
import * as signercollection from "./cms/signers"

export let DataFormat = dataFormat.DataFormat;
export let PublicExponent = publicExponent.PublicExponent;

export namespace pki {
    export let Certificate = cert.Certificate;
    export let CertificateCollection = certs.CertificateCollection;
    export let Crl = crl.Crl;
    export let CertStore = certstore.CertStore;
    export let ProviderSystem = providersystem.ProviderSystem;
    export let Key = key.Key;
    export let Oid = oid.Oid;
    export let Algorithm = alg.Algorithm;
    export let CertificationRequestInfo = certRegInfo.CertificationRequestInfo;
    export let CertificationRequest = certReg.CertificationRequest;
    export let CSR = csr.CSR;
    export let Cipher = cipher.Cipher;
}

export namespace cms {
    export let SignedData = signed_data.SignedData;
    export let SignedDataContentType = signed_data.SignedDataContentType;
    export let Signer = signer.Signer;
    export let SignerCollection = signercollection.SignerCollection;    
}