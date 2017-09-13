#include "../stdafx.h"

#include "wpkistore.h"
#include "wsystem.h"
#include "wcashjson.h"

#include "../pki/wcert.h"
#include "../pki/wcerts.h"
#include "../pki/wcrl.h"
#include "../pki/wcert_request.h"
#include "../pki/wkey.h"

#include <wrapper/common/common.h>
#include "../helper.h"

void WPkiStore::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("PkiStore").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "addProvider", AddProvider);
	Nan::SetPrototypeMethod(tpl, "addCert", AddCert);
	Nan::SetPrototypeMethod(tpl, "addCrl", AddCrl);
	Nan::SetPrototypeMethod(tpl, "addKey", AddKey);
	Nan::SetPrototypeMethod(tpl, "addCsr", AddCsr);
	Nan::SetPrototypeMethod(tpl, "find", Find);
	Nan::SetPrototypeMethod(tpl, "findKey", FindKey);
	Nan::SetPrototypeMethod(tpl, "getItem", GetItem);
	Nan::SetPrototypeMethod(tpl, "getCerts", GetCerts);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WPkiStore::New){
	METHOD_BEGIN();

	try{
		WPkiStore *obj = new WPkiStore();

		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *json = *v8Str;

		obj->data_ = new PkiStore(new std::string(json));

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiStore::AddProvider){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("provider");
		WProvider * wProv = WProvider::Unwrap<WProvider>(info[0]->ToObject());

		UNWRAP_DATA(PkiStore);

		_this->addProvider(wProv->data_);
						
		info.GetReturnValue().Set(info.This());
		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::AddCert){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("provider");
		WProvider * wProv = WProvider::Unwrap<WProvider>(info[0]->ToObject());

		LOGGER_ARG("category");
		v8::String::Utf8Value v8Category(info[1]->ToString());
		char *category = *v8Category;

		LOGGER_ARG("cert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[2]->ToObject());

		UNWRAP_DATA(PkiStore);	

		Handle<std::string> uri = _this->addPkiObject(wProv->data_, new std::string(category), wCert->data_);

		v8::Local<v8::String> v8Uri = Nan::New<v8::String>(uri->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Uri);
		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::AddCrl){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("provider");
		WProvider * wProv = WProvider::Unwrap<WProvider>(info[0]->ToObject());

		LOGGER_ARG("category");
		v8::String::Utf8Value v8Category(info[1]->ToString());
		char *category = *v8Category;

		LOGGER_ARG("crl");
		WCRL * wCrl = WCRL::Unwrap<WCRL>(info[2]->ToObject());

		UNWRAP_DATA(PkiStore);

		Handle<std::string> uri = _this->addPkiObject(wProv->data_, new std::string(category), wCrl->data_);

		v8::Local<v8::String> v8Uri = Nan::New<v8::String>(uri->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Uri);
		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::AddCsr){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("provider");
		WProvider * wProv = WProvider::Unwrap<WProvider>(info[0]->ToObject());

		LOGGER_ARG("category");
		v8::String::Utf8Value v8Category(info[1]->ToString());
		char *category = *v8Category;

		LOGGER_ARG("csr");
		WCertificationRequest * wCsr = WCertificationRequest::Unwrap<WCertificationRequest>(info[2]->ToObject());

		UNWRAP_DATA(PkiStore);
	
		Handle<std::string> uri = _this->addPkiObject(wProv->data_, new std::string(category), wCsr->data_);

		v8::Local<v8::String> v8Uri = Nan::New<v8::String>(uri->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Uri);
		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::AddKey){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("provider");
		WProvider * wProv = WProvider::Unwrap<WProvider>(info[0]->ToObject());

		LOGGER_ARG("key");
		WKey * wKey = WKey::Unwrap<WKey>(info[1]->ToObject());

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(PkiStore);	

		Handle<std::string> uri = _this->addPkiObject(wProv->data_, wKey->data_, new std::string(password));

		v8::Local<v8::String> v8Uri = Nan::New<v8::String>(uri->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Uri);
		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::Find){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("filter");
		WFilter * wFilter = WFilter::Unwrap<WFilter>(info[0]->ToObject());

		UNWRAP_DATA(PkiStore);

		Handle<PkiItemCollection> res = _this->find(wFilter->data_);

		v8::Isolate* isolate = v8::Isolate::GetCurrent();

		v8::Local<v8::Array> array8 = v8::Array::New(isolate, res->length());

		for (int i = 0; i < res->length(); i++){
			v8::Local<v8::Object> tempObj = v8::Object::New(isolate);
			Handle<PkiItem> item = res->items(i);

			tempObj->Set(v8::String::NewFromUtf8(isolate, "type"),
				v8::String::NewFromUtf8(isolate, item->type->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "format"),
				v8::String::NewFromUtf8(isolate, item->format->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "provider"),
				v8::String::NewFromUtf8(isolate, item->provider->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "category"),
				v8::String::NewFromUtf8(isolate, item->category->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "uri"),
				v8::String::NewFromUtf8(isolate, item->uri->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "hash"),
				v8::String::NewFromUtf8(isolate, item->hash->c_str()));

			if (strcmp(item->type->c_str(), "CERTIFICATE") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectName"),
					v8::String::NewFromUtf8(isolate, item->certSubjectName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectFriendlyName"),
					v8::String::NewFromUtf8(isolate, item->certSubjectFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerName"),
					v8::String::NewFromUtf8(isolate, item->certIssuerName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerFriendlyName"),
					v8::String::NewFromUtf8(isolate, item->certIssuerFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "notBefore"),
					v8::String::NewFromUtf8(isolate, item->certNotBefore->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "notAfter"),
					v8::String::NewFromUtf8(isolate, item->certNotAfter->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "serial"),
					v8::String::NewFromUtf8(isolate, item->certSerial->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "key"),
					v8::String::NewFromUtf8(isolate, item->certKey->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "organizationName"),
					v8::String::NewFromUtf8(isolate, item->certOrganizationName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "signatureAlgorithm"),
					v8::String::NewFromUtf8(isolate, item->certSignatureAlgorithm->c_str()));

				array8->Set(i, tempObj);
				continue;
			}

			if (strcmp(item->type->c_str(), "CRL") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerName"),
					v8::String::NewFromUtf8(isolate, item->crlIssuerName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerFriendlyName"),
					v8::String::NewFromUtf8(isolate, item->crlIssuerFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "lastUpdate"),
					v8::String::NewFromUtf8(isolate, item->crlLastUpdate->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "nextUpdate"),
					v8::String::NewFromUtf8(isolate, item->crlNextUpdate->c_str()));

				array8->Set(i, tempObj);
				continue;
			}

			if (strcmp(item->type->c_str(), "REQUEST") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectName"),
					v8::String::NewFromUtf8(isolate, item->csrSubjectName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectFriendlyName"),
					v8::String::NewFromUtf8(isolate, item->csrSubjectFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "key"),
					v8::String::NewFromUtf8(isolate, item->csrKey->c_str()));

				array8->Set(i, tempObj);
				continue;
			}	

			if (strcmp(item->type->c_str(), "KEY") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "encrypted"),
					v8::Boolean::New(isolate, item->keyEncrypted));

				array8->Set(i, tempObj);
				continue;
			}
		}

		info.GetReturnValue().Set(array8);
		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::FindKey){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("filter");
		WFilter * wFilter = WFilter::Unwrap<WFilter>(info[0]->ToObject());

		UNWRAP_DATA(PkiStore);

		Handle<PkiItem> res = _this->findKey(wFilter->data_);

		v8::Isolate* isolate = v8::Isolate::GetCurrent();

		v8::Local<v8::Object> tempObj = v8::Object::New(isolate);

		tempObj->Set(v8::String::NewFromUtf8(isolate, "type"),
			v8::String::NewFromUtf8(isolate, res->type->c_str()));

		tempObj->Set(v8::String::NewFromUtf8(isolate, "format"),
			v8::String::NewFromUtf8(isolate, res->format->c_str()));

		tempObj->Set(v8::String::NewFromUtf8(isolate, "provider"),
			v8::String::NewFromUtf8(isolate, res->provider->c_str()));

		tempObj->Set(v8::String::NewFromUtf8(isolate, "category"),
			v8::String::NewFromUtf8(isolate, res->category->c_str()));

		tempObj->Set(v8::String::NewFromUtf8(isolate, "uri"),
			v8::String::NewFromUtf8(isolate, res->uri->c_str()));

		tempObj->Set(v8::String::NewFromUtf8(isolate, "hash"),
			v8::String::NewFromUtf8(isolate, res->hash->c_str()));

		info.GetReturnValue().Set(tempObj);
		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::GetItem){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("item");
		WPkiItem * wItem = WPkiItem::Unwrap<WPkiItem>(info[0]->ToObject());

		UNWRAP_DATA(PkiStore);

		if (strcmp(wItem->data_->type->c_str(), "CERTIFICATE") == 0){
			Handle<Certificate> cert = _this->getItemCert(wItem->data_);
			v8::Local<v8::Object> v8Cert = WCertificate::NewInstance(cert);
			info.GetReturnValue().Set(v8Cert);
		}
		else if (strcmp(wItem->data_->type->c_str(), "CRL") == 0){
			Handle<CRL> crl = _this->getItemCrl(wItem->data_);
			v8::Local<v8::Object> v8Crl = WCRL::NewInstance(crl);
			info.GetReturnValue().Set(v8Crl);
		}
		else if (strcmp(wItem->data_->type->c_str(), "REQUEST") == 0){
			Handle<CertificationRequest> csr = _this->getItemReq(wItem->data_);
			v8::Local<v8::Object> v8Csr = WCertificationRequest::NewInstance(csr);
			info.GetReturnValue().Set(v8Csr);
		}
		else if (strcmp(wItem->data_->type->c_str(), "KEY") == 0){
			Handle<Key> key = _this->getItemKey(wItem->data_);
			v8::Local<v8::Object> v8Key = WKey::NewInstance(key);
			info.GetReturnValue().Set(v8Key);
		}

		return;
	}

	TRY_END();
}

NAN_METHOD(WPkiStore::GetCerts){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(PkiStore);
		
		info.GetReturnValue().Set(WCertificateCollection::NewInstance(_this->getCerts()));
		return;
	}

	TRY_END();
}

void WProvider::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Provider").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WProvider::New){
	METHOD_BEGIN();

	try{
		WProvider *obj = new WProvider();
		obj->data_ = new Provider();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}


void WFilter::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Filter").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "setType", SetType);
	Nan::SetPrototypeMethod(tpl, "setProvider", SetProvider);
	Nan::SetPrototypeMethod(tpl, "setCategory", SetCategory);
	Nan::SetPrototypeMethod(tpl, "setHash", SetHash);
	Nan::SetPrototypeMethod(tpl, "setSubjectName", SetSubjectName);
	Nan::SetPrototypeMethod(tpl, "setSubjectFriendlyName", SetSubjectFriendlyName);
	Nan::SetPrototypeMethod(tpl, "setIssuerName", SetIssuerName);
	Nan::SetPrototypeMethod(tpl, "setIssuerFriendlyName", SetIssuerFriendlyName);
	Nan::SetPrototypeMethod(tpl, "setSerial", SetSerial);
	//Nan::SetPrototypeMethod(tpl, "setIsValid", SetIsValid); ????????????????????

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WFilter::New){
	METHOD_BEGIN();

	try{
		WFilter *obj = new WFilter();
		obj->data_ = new Filter();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetType) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("type");
		v8::String::Utf8Value v8Type(info[0]->ToString());
		char *type = *v8Type;

		_this->setType(new std::string(type));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetProvider) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("provider");
		v8::String::Utf8Value v8Provider(info[0]->ToString());
		char *provider = *v8Provider;

		_this->setProvider(new std::string(provider));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetCategory) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("category");
		v8::String::Utf8Value v8Category(info[0]->ToString());
		char *category = *v8Category;

		_this->setCategory(new std::string(category));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetHash) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("hash");
		v8::String::Utf8Value v8Hash(info[0]->ToString());
		char *hash = *v8Hash;

		_this->setHash(new std::string(hash));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetSubjectName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("subjectName");
		v8::String::Utf8Value v8SubjectName(info[0]->ToString());
		char *subjectName = *v8SubjectName;

		_this->setSubjectName(new std::string(subjectName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetSubjectFriendlyName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("subjectFriendlyName");
		v8::String::Utf8Value v8SubjectFriendlyName(info[0]->ToString());
		char *subjectFriendlyName = *v8SubjectFriendlyName;

		_this->setSubjectFriendlyName(new std::string(subjectFriendlyName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetIssuerName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("issuerName");
		v8::String::Utf8Value v8IssuerName(info[0]->ToString());
		char *issuerName = *v8IssuerName;

		_this->setIssuerName(new std::string(issuerName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetIssuerFriendlyName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("issuerFriendlyName");
		v8::String::Utf8Value v8IssuerFriendlyName(info[0]->ToString());
		char *issuerFriendlyName = *v8IssuerFriendlyName;

		_this->setIssuerFriendlyName(new std::string(issuerFriendlyName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WFilter::SetSerial) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Filter);

		LOGGER_ARG("serial");
		v8::String::Utf8Value v8Serial(info[0]->ToString());
		char *serial = *v8Serial;

		_this->setSerial(new std::string(serial));
		return;
	}
	TRY_END();
}

void WPkiItem::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("PkiItem").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "setFormat", SetFormat);
	Nan::SetPrototypeMethod(tpl, "setType", SetType);
	Nan::SetPrototypeMethod(tpl, "setProvider", SetProvider);
	Nan::SetPrototypeMethod(tpl, "setCategory", SetCategory);
	Nan::SetPrototypeMethod(tpl, "setURI", SetURI);
	Nan::SetPrototypeMethod(tpl, "setHash", SetHash);
	Nan::SetPrototypeMethod(tpl, "setSubjectName", SetSubjectName);
	Nan::SetPrototypeMethod(tpl, "setSubjectFriendlyName", SetSubjectFriendlyName);
	Nan::SetPrototypeMethod(tpl, "setIssuerName", SetIssuerName);
	Nan::SetPrototypeMethod(tpl, "setIssuerFriendlyName", SetIssuerFriendlyName);
	Nan::SetPrototypeMethod(tpl, "setSerial", SetSerial);
	Nan::SetPrototypeMethod(tpl, "setNotBefore", SetNotBefore);
	Nan::SetPrototypeMethod(tpl, "setNotAfter", SetNotAfter);
	Nan::SetPrototypeMethod(tpl, "setLastUpdate", SetLastUpdate);
	Nan::SetPrototypeMethod(tpl, "setNextUpdate", SetNextUpdate);
	Nan::SetPrototypeMethod(tpl, "setKey", SetKey);
	Nan::SetPrototypeMethod(tpl, "setKeyEncrypted", SetKeyEncrypted);
	Nan::SetPrototypeMethod(tpl, "setOrganizationName", SetOrganizationName);
	Nan::SetPrototypeMethod(tpl, "setSignatureAlgorithm", SetSignatureAlgorithm);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WPkiItem::New){
	METHOD_BEGIN();

	try{
		WPkiItem *obj = new WPkiItem();

		obj->data_ = new PkiItem();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetFormat) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("format");
		v8::String::Utf8Value v8Format(info[0]->ToString());
		char *format = *v8Format;

		_this->setFormat(new std::string(format));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetType) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("type");
		v8::String::Utf8Value v8Type(info[0]->ToString());
		char *type = *v8Type;

		_this->setType(new std::string(type));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetProvider) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("provider");
		v8::String::Utf8Value v8Provider(info[0]->ToString());
		char *provider = *v8Provider;

		_this->setProvider(new std::string(provider));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetCategory) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("category");
		v8::String::Utf8Value v8Category(info[0]->ToString());
		char *category = *v8Category;

		_this->setCategory(new std::string(category));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetURI) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("uri");
		v8::String::Utf8Value v8Uri(info[0]->ToString());
		char *uri = *v8Uri;

		_this->setURI(new std::string(uri));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetHash) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("hash");
		v8::String::Utf8Value v8Hash(info[0]->ToString());
		char *hash = *v8Hash;

		_this->setHash(new std::string(hash));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetSubjectName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("subjectName");
		v8::String::Utf8Value v8SubjectName(info[0]->ToString());
		char *subjectName = *v8SubjectName;

		_this->setSubjectName(new std::string(subjectName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetSubjectFriendlyName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("subjectFriendlyName");
		v8::String::Utf8Value v8SubjectFriendlyName(info[0]->ToString());
		char *subjectFriendlyName = *v8SubjectFriendlyName;

		_this->setSubjectFriendlyName(new std::string(subjectFriendlyName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetIssuerName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("issuerName");
		v8::String::Utf8Value v8IssuerName(info[0]->ToString());
		char *issuerName = *v8IssuerName;

		_this->setIssuerName(new std::string(issuerName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetIssuerFriendlyName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("issuerFriendlyName");
		v8::String::Utf8Value v8IssuerFriendlyName(info[0]->ToString());
		char *issuerFriendlyName = *v8IssuerFriendlyName;

		_this->setIssuerFriendlyName(new std::string(issuerFriendlyName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetSerial) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("serial");
		v8::String::Utf8Value v8Serial(info[0]->ToString());
		char *serial = *v8Serial;

		_this->setSerial(new std::string(serial));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetNotBefore) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("before");
		v8::String::Utf8Value v8Before(info[0]->ToString());
		char *before = *v8Before;

		_this->setNotBefore(new std::string(before));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetNotAfter) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("after");
		v8::String::Utf8Value v8After(info[0]->ToString());
		char *after = *v8After;

		_this->setNotAfter(new std::string(after));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetLastUpdate) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("last");
		v8::String::Utf8Value v8Last(info[0]->ToString());
		char *last = *v8Last;

		_this->setLastUpdate(new std::string(last));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetNextUpdate) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("next");
		v8::String::Utf8Value v8Next(info[0]->ToString());
		char *next = *v8Next;

		_this->setNextUpdate(new std::string(next));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetKey) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("key");
		v8::String::Utf8Value v8Key(info[0]->ToString());
		char *key = *v8Key;

		_this->setKey(new std::string(key));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetKeyEncrypted) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("encrypted");
		v8::Local<v8::Boolean> v8Enc = info[0]->ToBoolean();

		_this->setKeyEncypted(v8Enc->BooleanValue());
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetOrganizationName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("organizationName");
		v8::String::Utf8Value v8OrganizationName(info[0]->ToString());
		char *organizationName = *v8OrganizationName;

		_this->setOrganizationName(new std::string(organizationName));
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkiItem::SetSignatureAlgorithm) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(PkiItem);

		LOGGER_ARG("signatureAlgorithm");
		v8::String::Utf8Value v8SignatureAlgorithm(info[0]->ToString());
		char *signatureAlgorithm = *v8SignatureAlgorithm;

		_this->setSignatureAlgorithm(new std::string(signatureAlgorithm));
		return;
	}
	TRY_END();
}
