#include "stdafx.h"

#include <locale>
#include <clocale>

#include <openssl/cms.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include <nan.h>

#include "common/wopenssl.h"

#include "utils/wlog.h"
#include "utils/wjwt.h"
#include "utils/wcsp.h"

#include "pki/wkey.h"
#include "pki/wcert.h"
#include "pki/wpkcs12.h"
#include "pki/wcerts.h"
#include "pki/wcrl.h"
#include "pki/wrevoked.h"
#include "pki/wrevokeds.h"
#include "pki/wcrls.h"
#include "pki/woid.h"
#include "pki/walg.h"
#include "pki/wattr.h"
#include "pki/wext.h"
#include "pki/wcert_request_info.h"
#include "pki/wcert_request.h"
#include "pki/wcipher.h"
#include "pki/wchain.h"
#include "pki/wrevocation.h"
#include "store/wpkistore.h"
#include "store/wsystem.h"
#if defined(OPENSSL_SYS_WINDOWS)
#include "store/wmicrosoft.h"
#endif
#if defined(CPROCSP)
#include "store/wcryptopro.h"
#endif
#include "store/wcashjson.h"

#include "cms/wsigned_data.h"
#include "cms/wsigner.h"
#include "cms/wsigners.h"
#include "cms/wsigner_id.h"
#include "cms/wsigner_attrs.h"
#include "cms/wcmsRecipientInfo.h"
#include "cms/wcmsRecipientInfos.h"

#include <node_object_wrap.h>

void init(v8::Handle<v8::Object> target) {
	// logger.start("/tmp/trustedtls/node.log", -1); // -1 = all levels bits
	// logger->start("logger.txt", LoggerLevel::All );

	// On Windows, we can't use Node's OpenSSL, so we link
	// to a standalone OpenSSL library. Therefore, we need
	// to initialize OpenSSL separately.

	// TODO: Do I need to free these?
	// I'm not sure where to call ERR_free_strings() and EVP_cleanup()

	// LOGGER_TRACE("OpenSSL init");

	std::setlocale(LC_ALL, "");

	OpenSSL::run();

	v8::Local<v8::Object> OpenSSL = Nan::New<v8::Object>();

	target->Set(Nan::New("COMMON").ToLocalChecked(), OpenSSL);
	WOpenSSL::Init(OpenSSL);

	v8::Local<v8::Object> Utils = Nan::New<v8::Object>();

	target->Set(Nan::New("UTILS").ToLocalChecked(), Utils);
	WJwt::Init(Utils);
	WLogger::Init(Utils);
	WCsp::Init(Utils);

	v8::Local<v8::Object> Pki = Nan::New<v8::Object>();

	target->Set(Nan::New("PKI").ToLocalChecked(), Pki);
	WCertificate::Init(Pki);
	WCertificateCollection::Init(Pki);
	WCRL::Init(Pki);
	WCrlCollection::Init(Pki);
	WRevoked::Init(Pki);
	WRevokedCollection::Init(Pki);
	WOID::Init(Pki);
	WAlgorithm::Init(Pki);
	WAttribute::Init(Pki);
	WExtension::Init(Pki);
	WKey::Init(Pki);
	WCertificationRequestInfo::Init(Pki);
	WCertificationRequest::Init(Pki);
	WCipher::Init(Pki);
	WChain::Init(Pki);
	WPkcs12::Init(Pki);
	WRevocation::Init(Pki);


	v8::Local<v8::Object> Cms = Nan::New<v8::Object>();
	target->Set(Nan::New("CMS").ToLocalChecked(), Cms);
	WSignedData::Init(Cms);
	WSigner::Init(Cms);
	WSignerCollection::Init(Cms);
	WSignerId::Init(Cms);
	WSignerAttributeCollection::Init(Cms);
	WCmsRecipientInfo::Init(Cms);
	WCmsRecipientInfoCollection::Init(Cms);

	v8::Local<v8::Object> PkiStore = Nan::New<v8::Object>();
	target->Set(Nan::New("PKISTORE").ToLocalChecked(), PkiStore);
	WPkiStore::Init(PkiStore);
	WProvider_System::Init(PkiStore);
#if defined(OPENSSL_SYS_WINDOWS)
	WProviderMicrosoft::Init(PkiStore);
#endif
#if defined(CPROCSP)
	WProviderCryptopro::Init(PkiStore);
#endif
	WFilter::Init(PkiStore);
	WPkiItem::Init(PkiStore);
	WCashJson::Init(PkiStore);
}

NODE_MODULE(trusted, init)
