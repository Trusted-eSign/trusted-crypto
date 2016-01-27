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

	static Handle<Key> generate();
	void load(std::string filename);
	void read(Handle<Bio> in);
	Handle<Key> publicKey();
	bool compare(Handle<Key>&);
	Handle<Key> duplicate();

	KeyType type;

	int privkeyLoad(std::string filename, DataFormat::DATA_FORMAT format, std::string password); //чтение приватного ключа из файла
	int privkeyLoadMemory(std::string data, DataFormat::DATA_FORMAT format, std::string password); //чтение приватного ключа из памяти
	int privkeyLoadBIO(BIO* bio, DataFormat::DATA_FORMAT format, std::string password); //чтение приватного ключа из BIO(OpenSSL)

	int pubkeyLoad(std::string filename, DataFormat::DATA_FORMAT format); //чтение публичного ключа из файла
	int pubkeyLoadMemory(std::string data, DataFormat::DATA_FORMAT format); //чтение приватного ключа из памяти
	int pubkeyLoadBIO(BIO* bio, DataFormat::DATA_FORMAT format); //чтение приватного ключа из BIO(OpenSSL)

	int keypairGenerate(std::string filename, DataFormat::DATA_FORMAT format, PublicExponent::Public_Exponent pubEx, int keySize, std::string password); //генерация ключей в файл
	int keypairGenerateMemory(std::string data, DataFormat::DATA_FORMAT format, PublicExponent::Public_Exponent pubEx, int keySize, std::string password); //генерация ключей в память
	int keypairGenerateBIO(Handle<Bio> bio, DataFormat::DATA_FORMAT format, PublicExponent::Public_Exponent pubEx, int keySize, std::string password); //генерация ключей в BIO(OpenSSL)

	int privkeySave(std::string filename, DataFormat::DATA_FORMAT format, std::string password); //сохранение приватного ключа в файл
	int privkeySaveMemory(std::string data, DataFormat::DATA_FORMAT format, std::string password); //сохранение приватного ключа в файл
	int privkeySaveBIO(Handle<Bio> out, DataFormat::DATA_FORMAT format, std::string password); //сохранение приватного ключа в файл

	int pubkeySave(std::string filename, DataFormat::DATA_FORMAT format); //сохранение публичного ключа в файл
	int pubkeySaveMemory(std::string data, DataFormat::DATA_FORMAT format); //сохранение публичного ключа в память
	int pubkeySaveBIO(Handle<Bio> out, DataFormat::DATA_FORMAT format); //сохранение публичного ключа в BIO(OpenSSL)
};

#endif //  comment this --->   CMS_PKI_KEY_H_INCLUDED
