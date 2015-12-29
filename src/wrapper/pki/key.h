#ifndef CMS_PKI_KEY_H_INCLUDED
#define  CMS_PKI_KEY_H_INCLUDED

#include <openssl/evp.h>

#include "../common/common.h"

class CTWRAPPER_API Key;

#include "pki.h"

enum KeyType {
	KT_NONE,
	KT_PRIVATE,
	KT_PUBLIC //добавлено KT_ во всех 3-х случах
};

//class Key;
//typedef RCIPtr < Key > KeyPtr;

SSLOBJECT_free(EVP_PKEY, EVP_PKEY_free)

class Key: public SSLObject<EVP_PKEY>{
public:
	SSLOBJECT_new(Key, EVP_PKEY){}
	SSLOBJECT_new_null(Key, EVP_PKEY, EVP_PKEY_new){}

	static Handle<Key> generate();
	void load(std::string filename);
	void read(Handle<Bio> in);
	Handle<Key> publicKey();
	bool compare(Handle<Key>&);
	Handle<Key> duplicate();

	KeyType type;
};

#endif //  comment this --->   CMS_PKI_KEY_H_INCLUDED
