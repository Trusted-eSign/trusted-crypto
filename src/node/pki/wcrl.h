#ifndef PKI_WCRL_H_INCLUDED
#define  PKI_WCRL_H_INCLUDED

#include "../../wrapper/pki/crl.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(CRL){
public:
	WCRL(){};
	~WCRL(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Load);
	static NAN_METHOD(Import);
	static NAN_METHOD(Save);
	static NAN_METHOD(Export);
	static NAN_METHOD(Equals);
	static NAN_METHOD(Compare);
	static NAN_METHOD(Duplicate);
	static NAN_METHOD(Hash);

	static NAN_METHOD(GetEncoded);
	static NAN_METHOD(GetSignature);
	static NAN_METHOD(GetVersion);
	static NAN_METHOD(GetIssuerName);
	static NAN_METHOD(GetIssuerFriendlyName);
	static NAN_METHOD(GetLastUpdate);
	static NAN_METHOD(GetNextUpdate);
	static NAN_METHOD(GetCertificate);
	static NAN_METHOD(GetThumbprint);
	static NAN_METHOD(GetSigAlgName);
	static NAN_METHOD(GetSigAlgShortName);
	static NAN_METHOD(GetSigAlgOID);

	static NAN_METHOD(GetRevokedCertificateCert);
	static NAN_METHOD(GetRevokedCertificateSerial);

	WRAP_NEW_INSTANCE(CRL);
};

#endif //PKI_WCRL_H_INCLUDED
