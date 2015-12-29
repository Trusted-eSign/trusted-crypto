import * as cert from './pki/cert'
import * as crl from './pki/crl'

var i = 1;

export namespace Pki {
	export var Certificate = cert.Certificate;
	export var Crl = crl.Crl;
}