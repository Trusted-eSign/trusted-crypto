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
		WCashJson *obj = new WCashJson();

		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *json = *v8Str;

		obj->data_ = new CashJson(new std::string(json));

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
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

			tempObj->Set(v8::String::NewFromUtf8(isolate, "type"),
				v8::String::NewFromUtf8(isolate, res->items(i)->type->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "format"),
				v8::String::NewFromUtf8(isolate, res->items(i)->format->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "provider"),
				v8::String::NewFromUtf8(isolate, res->items(i)->provider->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "category"),
				v8::String::NewFromUtf8(isolate, res->items(i)->category->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "uri"),
				v8::String::NewFromUtf8(isolate, res->items(i)->uri->c_str()));

			tempObj->Set(v8::String::NewFromUtf8(isolate, "hash"),
				v8::String::NewFromUtf8(isolate, res->items(i)->hash->c_str()));

			if (strcmp(res->items(i)->type->c_str(), "CERTIFICATE") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certSubjectName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectFriendlyName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certSubjectFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certIssuerName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerFriendlyName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certIssuerFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "notBefore"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certNotBefore->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "notAfter"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certNotAfter->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "serial"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certSerial->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "key"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certKey->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "organizationName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certOrganizationName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "signatureAlgorithm"),
					v8::String::NewFromUtf8(isolate, res->items(i)->certSignatureAlgorithm->c_str()));

				array8->Set(i, tempObj);
				continue;
			}

			if (strcmp(res->items(i)->type->c_str(), "CRL") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->crlIssuerName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "issuerFriendlyName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->crlIssuerFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "lastUpdate"),
					v8::String::NewFromUtf8(isolate, res->items(i)->crlLastUpdate->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "nextUpdate"),
					v8::String::NewFromUtf8(isolate, res->items(i)->crlNextUpdate->c_str()));

				array8->Set(i, tempObj);
				continue;
			}

			if (strcmp(res->items(i)->type->c_str(), "REQUEST") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->csrSubjectName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "subjectFriendlyName"),
					v8::String::NewFromUtf8(isolate, res->items(i)->csrSubjectFriendlyName->c_str()));

				tempObj->Set(v8::String::NewFromUtf8(isolate, "key"),
					v8::String::NewFromUtf8(isolate, res->items(i)->csrKey->c_str()));

				array8->Set(i, tempObj);
				continue;
			}

			if (strcmp(res->items(i)->type->c_str(), "KEY") == 0){
				tempObj->Set(v8::String::NewFromUtf8(isolate, "encrypted"),
					v8::Boolean::New(isolate, res->items(i)->keyEncrypted));

				array8->Set(i, tempObj);
				continue;
			}
		}

		info.GetReturnValue().Set(array8);
		return;
	}

	TRY_END();
}