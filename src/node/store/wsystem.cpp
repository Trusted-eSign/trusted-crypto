#include "../stdafx.h"

#include "wsystem.h"
#include "wpkistore.h"

void WProvider_System::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Provider_System").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "objectToPkiItem", ObjectToPkiItem);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WProvider_System::New){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("folder");
		v8::String::Utf8Value v8Folder(info[0]->ToString());
		char *folder = *v8Folder;

		WProvider_System *obj = new WProvider_System();
		Handle<std::string> str = new std::string(folder);
		obj->data_ = new Provider_System(str);

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WProvider_System::ObjectToPkiItem){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Provider_System);

		LOGGER_ARG("path");
		v8::String::Utf8Value v8Path(info[0]->ToString());
		char *path = *v8Path;

		Handle<PkiItem> res = _this->objectToPKIItem(new std::string(path));

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

		if (strcmp(res->type->c_str(), "CERTIFICATE") == 0){
			tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectName"),
				v8::String::NewFromUtf8(isolate, res->certSubjectName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectFriendlyName"),
				v8::String::NewFromUtf8(isolate, res->certSubjectFriendlyName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerName"),
				v8::String::NewFromUtf8(isolate, res->certIssuerName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerFriendlyName"),
				v8::String::NewFromUtf8(isolate, res->certIssuerFriendlyName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "notBefore"),
				v8::String::NewFromUtf8(isolate, res->certNotBefore->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "notAfter"),
				v8::String::NewFromUtf8(isolate, res->certNotAfter->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "serial"),
				v8::String::NewFromUtf8(isolate, res->certSerial->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "key"),
				v8::String::NewFromUtf8(isolate, res->certKey->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "organizationName"),
				v8::String::NewFromUtf8(isolate, res->certOrganizationName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "signatureAlgorithm"),
				v8::String::NewFromUtf8(isolate, res->certSignatureAlgorithm->c_str()));
		}

		if (strcmp(res->type->c_str(), "CRL") == 0){
			tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerName"),
				v8::String::NewFromUtf8(isolate, res->crlIssuerName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerFriendlyName"),
				v8::String::NewFromUtf8(isolate, res->crlIssuerFriendlyName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "lastUpdate"),
				v8::String::NewFromUtf8(isolate, res->crlLastUpdate->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "nextUpdate"),
				v8::String::NewFromUtf8(isolate, res->crlNextUpdate->c_str()));
		}

		if (strcmp(res->type->c_str(), "REQUEST") == 0){
			tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectName"),
				v8::String::NewFromUtf8(isolate, res->csrSubjectName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectFriendlyName"),
				v8::String::NewFromUtf8(isolate, res->csrSubjectFriendlyName->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "key"),
				v8::String::NewFromUtf8(isolate, res->csrKey->c_str()));
		}

		if (strcmp(res->type->c_str(), "KEY") == 0){
			tempObj->Set(v8::String::NewFromUtf8(isolate, "encrypted"),
				v8::Boolean::New(isolate, res->keyEncrypted));
		}

		info.GetReturnValue().Set(tempObj);
		return;
	}
	TRY_END();
}