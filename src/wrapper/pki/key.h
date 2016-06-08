#ifndef CMS_PKI_KEY_H_INCLUDED
#define  CMS_PKI_KEY_H_INCLUDED

#include <openssl/evp.h>

#include "../common/common.h"

class CTWRAPPER_API Key;

#include "pki.h"

class PublicExponent
{
public:
	enum Public_Exponent {
		peRSA_3,
		peRSA_F4
	};

	static PublicExponent::Public_Exponent get(int value){
		switch (value){
		case PublicExponent::peRSA_3:
			return PublicExponent::peRSA_3;
		case PublicExponent::peRSA_F4:
			return PublicExponent::peRSA_F4;
		default:
			THROW_EXCEPTION(0, PublicExponent, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, value);
		}
	}
};

SSLOBJECT_free(EVP_PKEY, EVP_PKEY_free)

class Key: public SSLObject<EVP_PKEY>{

public:
	SSLOBJECT_new(Key, EVP_PKEY){}
	SSLOBJECT_new_null(Key, EVP_PKEY, EVP_PKEY_new){}

	//Methods
	void readPrivateKey(Handle<Bio> in, DataFormat::DATA_FORMAT format, Handle<std::string> password);
	void writePrivateKey(Handle<Bio> out, DataFormat::DATA_FORMAT format, Handle<std::string> password);

	void readPublicKey(Handle<Bio> in, DataFormat::DATA_FORMAT format);
	void writePublicKey(Handle<Bio> out, DataFormat::DATA_FORMAT format);

	Handle<Key> generate(DataFormat::DATA_FORMAT format, PublicExponent::Public_Exponent pubEx, int keySize);
	int compare(Handle<Key> key);
	Handle<Key> duplicate();
};

#endif

