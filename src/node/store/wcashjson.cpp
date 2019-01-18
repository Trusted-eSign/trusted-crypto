#include "../stdafx.h"

#include "wcashjson.h"
#include "wpkistore.h"

void WCashJson::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("CashJson").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "import", Import);
	Nan::SetPrototypeMethod(tpl, "export", Export);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCashJson::New){
	METHOD_BEGIN();

	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}
		else {
			WCashJson *obj = new WCashJson();

#if defined(OPENSSL_SYS_WINDOWS)
			LPCWSTR wCont = (LPCWSTR)* v8::String::Value(info[0]->ToString());

			int string_len = WideCharToMultiByte(CP_ACP, 0, wCont, -1, NULL, 0, NULL, NULL);
			if (!string_len) {
				Nan::ThrowError("Error WideCharToMultiByte");
			}

			char* converted = new char[string_len];
			if (!converted) {
				Nan::ThrowError("Error LocalAlloc");
			}

			string_len = WideCharToMultiByte(CP_ACP, 0, wCont, -1, converted, string_len, NULL, NULL);
			if (!string_len)
			{
				delete[] converted;
				Nan::ThrowError("Error WideCharToMultiByte");
			}

			std::string result = converted;

			delete[] converted;

			const char *json = result.c_str();
#else
			v8::String::Utf8Value v8Str(info[0]->ToString());
			char *json = *v8Str;
#endif // OPENSSL_SYS_WINDOWS
			obj->data_ = new CashJson(new std::string(json));

			obj->Wrap(info.This());

			info.GetReturnValue().Set(info.This());
			return;
		}
	}
	TRY_END();
}

NAN_METHOD(WCashJson::Import) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("items");
		WPkiItem * wItem = WPkiItem::Unwrap<WPkiItem>(info[0]->ToObject());

		UNWRAP_DATA(CashJson);

		_this->importJson(wItem->data_);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCashJson::Export) {
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CashJson);

		Handle<PkiItemCollection> res = _this->exportJson();

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

				tempObj->Set(v8::String::NewFromUtf8(isolate, "signatureDigestAlgorithm"),
					v8::String::NewFromUtf8(isolate, item->certSignatureDigestAlgorithm->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "publicKeyAlgorithm"),
					v8::String::NewFromUtf8(isolate, item->certPublicKeyAlgorithm->c_str()));

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

				tempObj->Set(v8::String::NewFromUtf8(isolate, "signatureAlgorithm"),
					v8::String::NewFromUtf8(isolate, item->crlSignatureAlgorithm->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "signatureDigestAlgorithm"),
					v8::String::NewFromUtf8(isolate, item->crlSignatureDigestAlgorithm->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "authorityKeyid"),
					v8::String::NewFromUtf8(isolate, item->crlAuthorityKeyid->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "crlNumber"),
					v8::String::NewFromUtf8(isolate, item->crlCrlNumber->c_str()));

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