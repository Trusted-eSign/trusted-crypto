import * as dataFormat from "./data_format";
import * as cert from "./pki/cert";
import * as crl from "./pki/crl";

export let DataFormat = dataFormat.DataFormat;

export namespace Pki {
    export let Certificate = cert.Certificate;
    export let Crl = crl.Crl;
}