#ifndef WCASHJSON_H_INCLUDED
#define WCASHJSON_H_INCLUDED

#include "../../wrapper/store/pkistore.h"
#include "../../wrapper/store/cashjson.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(CashJson){
public:
	WCashJson(){};
	~WCashJson(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Import);
	static NAN_METHOD(Export);

	WRAP_NEW_INSTANCE(CashJson);
};

#endif //WCASHJSON_H_INCLUDED
