/* tslint:disable:no-namespace */

import * as dataFormat from "./data_format";
import * as publicExponent from "./public_exponent";
import * as cryptoMethod from "./crypto_method";
import * as cert from "./pki/cert";
import * as certs from "./pki/certs";
import * as crl from "./pki/crl";
import * as crls from "./pki/crls";
import * as key from "./pki/key";
import * as oid from "./pki/oid";
import * as alg from "./pki/alg";
import * as certRegInfo from "./pki/certRegInfo";
import * as certReg from "./pki/certReg";
import * as csr from "./pki/csr";
import * as cipher from "./pki/cipher";
import * as chain from "./pki/chain";
import * as revocation from "./pki/revocation";
import * as pkcs12 from "./pki/pkcs12";

import * as signed_data from "./cms/signed_data";
import * as signer from "./cms/signer";
import * as signercollection from "./cms/signers";

import * as store from "./pkistore/pkistore";
import * as provider_system from "./pkistore/psystem";
import * as provider_microsoft from "./pkistore/pmicrosoft";
import * as provider_cryptopro from "./pkistore/pcryptopro";
import * as cashjson from "./pkistore/cashjson";

export let DataFormat = dataFormat.DataFormat;
export let PublicExponent = publicExponent.PublicExponent;
export let CryptoMethod = cryptoMethod.CryptoMethod;

export namespace pki {
    export let Certificate = cert.Certificate;
    export let CertificateCollection = certs.CertificateCollection;
    export let Crl = crl.Crl;
    export let CrlCollection = crls.CrlCollection;
    export let Key = key.Key;
    export let Oid = oid.Oid;
    export let Algorithm = alg.Algorithm;
    export let CertificationRequestInfo = certRegInfo.CertificationRequestInfo;
    export let CertificationRequest = certReg.CertificationRequest;
    export let CSR = csr.CSR;
    export let Cipher = cipher.Cipher;
    export let Chain = chain.Chain;
    export let Revocation = revocation.Revocation;
    export let Pkcs12 = pkcs12.Pkcs12;
}

export namespace cms {
    export let SignedData = signed_data.SignedData;
    export let SignedDataContentType = signed_data.SignedDataContentType;
    export let Signer = signer.Signer;
    export let SignerCollection = signercollection.SignerCollection;
}

export namespace pkistore {
    export let PkiStore = store.PkiStore;
    /* tslint:disable-next-line:variable-name */
    export let Provider_System = provider_system.Provider_System;
    export let ProviderMicrosoft = provider_microsoft.ProviderMicrosoft;
    export let ProviderCryptopro = provider_cryptopro.ProviderCryptopro;
    export let CashJson = cashjson.CashJson;
}
