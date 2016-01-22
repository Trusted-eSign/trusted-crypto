#include "../stdafx.h"

#include <openssl/cms.h>
#include <openssl/err.h>

#include "key.h"

void Key::load(std::string filename) {
	Handle<Bio> in = new Bio(BIO_TYPE_FILE, filename, "rb");
	this->read(in);
}

int Key::privkeyLoad(std::string filename, DataFormat::DATA_FORMAT format, std::string password) {
	try{
		Handle<Bio> in = new Bio(BIO_TYPE_FILE, filename, "rb");
		EVP_PKEY *key = NULL;
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();

		const void * pass = password.c_str();

		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(d2i_PKCS8PrivateKey_bio);
			key = d2i_PKCS8PrivateKey_bio(in->internal(), NULL, 0, (void *)pass);
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_read_bio_PrivateKey);
			key = PEM_read_bio_PrivateKey(in->internal(), NULL, 0, (void *)pass);
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}

		if (!key) {
			THROW_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data from file");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		return -1;
	}
	
	return 0;
}

int Key::privkeyLoadMemory(std::string data, DataFormat::DATA_FORMAT format, std::string password) {
	try{
		Handle<Bio> in = new Bio(BIO_TYPE_MEM, data, "rb");
		EVP_PKEY *key = NULL;
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();

		const void * pass = password.c_str();

		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(d2i_PKCS8PrivateKey_bio);
			key = d2i_PKCS8PrivateKey_bio(in->internal(), NULL, 0, (void *)pass);
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_read_bio_PrivateKey);
			key = PEM_read_bio_PrivateKey(in->internal(), NULL, 0, (void *)pass);
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}

		if (!key) {
			THROW_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data from memory");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::privkeyLoadBIO(BIO* bio, DataFormat::DATA_FORMAT format, std::string password) {
	try{
		Handle<Bio> in = new Bio(bio);
		EVP_PKEY *key = NULL;
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();

		const void * pass = password.c_str();

		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(d2i_PKCS8PrivateKey_bio);
			key = d2i_PKCS8PrivateKey_bio(in->internal(), NULL, 0, (void *)pass);
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_read_bio_PrivateKey);
			key = PEM_read_bio_PrivateKey(in->internal(), NULL, 0, (void *)pass);
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}

		if (!key) {
			THROW_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data from file");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::pubkeyLoad(std::string filename, DataFormat::DATA_FORMAT format) {
	try{
		Handle<Bio> in = new Bio(BIO_TYPE_FILE, filename, "rb");
		EVP_PKEY *key = NULL;
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();
		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(d2i_PUBKEY_bio);
			key = d2i_PUBKEY_bio(in->internal(), NULL);
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_read_bio_PUBKEY);
			key = PEM_read_bio_PUBKEY(in->internal(), NULL, 0, NULL);
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}

		if (!key) {
			THROW_EXCEPTION(0, Key, NULL, "Can not read PUBKEY data from file");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::pubkeyLoadMemory(std::string data, DataFormat::DATA_FORMAT format) {
	try{
		Handle<Bio> in = new Bio(BIO_TYPE_MEM, data, "rb");
		EVP_PKEY *key = NULL;
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();
		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(d2i_PUBKEY_bio);
			key = d2i_PUBKEY_bio(in->internal(), NULL);
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_read_bio_PUBKEY);
			key = PEM_read_bio_PUBKEY(in->internal(), NULL, 0, NULL);
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}

		if (!key) {
			THROW_EXCEPTION(0, Key, NULL, "Can not read PUBKEY data from file");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::pubkeyLoadBIO(BIO* bio, DataFormat::DATA_FORMAT format) {
	try{
		Handle<Bio> in = new Bio(bio);
		EVP_PKEY *key = NULL;
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();
		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(d2i_PUBKEY_bio);
			key = d2i_PUBKEY_bio(in->internal(), NULL);
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_read_bio_PUBKEY);
			key = PEM_read_bio_PUBKEY(in->internal(), NULL, 0, NULL);
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}

		if (!key) {
			THROW_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data from file");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::keypairGenerate(std::string filename, DataFormat::DATA_FORMAT format, int keySize, std::string password){
	LOGGER_FN();

	int ok = 0;

	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
	EVP_PKEY *evpkey = NULL;
	BIO *bp_private = NULL;

	try{
		ENGINE *en = NULL;

		LOGGER_OPENSSL(RSA_new_method);
		rsa = RSA_new_method(en);
		if (!rsa){
			THROW_EXCEPTION(0, Key, NULL, "RSA_new_method");
		}

		LOGGER_OPENSSL(BN_new);
		bn = BN_new();
		if (!bn){
			THROW_EXCEPTION(0, Key, NULL, "BN_new");
		}
		
		LOGGER_OPENSSL(EVP_PKEY_new);
		evpkey = EVP_PKEY_new();
		if (!evpkey){
			THROW_EXCEPTION(0, Key, NULL, "EVP_PKEY_new");
		}

		LOGGER_OPENSSL(BN_set_word);
		if (!BN_set_word(bn, RSA_F4)){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "BN_set_word 'Unable set RSA_F4 to BIGNUM'");
		}
		
		if (keySize == NULL){
			keySize = 1024;
		}
		else{
			if (keySize < 1024){
				THROW_EXCEPTION(0, Key, NULL, "Key sizes should num > 1024 (else insecure)");
			}
		}

		LOGGER_OPENSSL(RSA_generate_key_ex);
		if (!RSA_generate_key_ex(rsa, keySize, bn, NULL)){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "RSA_generate_key_ex 'Unable  generates a key pair'");
		}

		LOGGER_OPENSSL(EVP_PKEY_set1_RSA);
		EVP_PKEY_set1_RSA(evpkey, rsa);

		LOGGER_OPENSSL(BIO_new_file);
		bp_private = BIO_new_file(filename.c_str(), "w+");
		if (!bp_private){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "BIO_new_file 'Unable creates a new file BIO'");
		}

		switch (format){
		case DataFormat::DER:
			if ((password).length() > 0){
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(bp_private, evpkey, EVP_aes_256_cbc(), (char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(bp_private, evpkey, NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			break;			
		case DataFormat::BASE64:
			if ((password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(bp_private, evpkey, EVP_aes_256_cbc(), (unsigned char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(bp_private, evpkey, NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		ok = -1;
	}

	if (bp_private){
		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(bp_private);
	}

	if (rsa){
		LOGGER_OPENSSL(RSA_free);
		RSA_free(rsa);
	}

	if (bn){
		LOGGER_OPENSSL(BN_free)
			BN_free(bn);
	}

	if (evpkey){
		LOGGER_OPENSSL(EVP_PKEY_free);
		EVP_PKEY_free(evpkey);
	}

	return ok;
}

int Key::keypairGenerateMemory(std::string data, DataFormat::DATA_FORMAT format, int keySize, std::string password){
	LOGGER_FN();

	int ok = 0;

	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
	EVP_PKEY *evpkey = NULL;
	BIO *bp_private = NULL;
	
	try{
		ENGINE *en = NULL;

		LOGGER_OPENSSL(RSA_new_method);
		rsa = RSA_new_method(en);
		if (!rsa){
			THROW_EXCEPTION(0, Key, NULL, "RSA_new_method");
		}

		LOGGER_OPENSSL(BN_new);
		bn = BN_new();
		if (!bn){
			THROW_EXCEPTION(0, Key, NULL, "BN_new");
		}

		LOGGER_OPENSSL(EVP_PKEY_new);
		evpkey = EVP_PKEY_new();
		if (!evpkey){
			THROW_EXCEPTION(0, Key, NULL, "EVP_PKEY_new");
		}

		LOGGER_OPENSSL(BN_set_word);
		if (!BN_set_word(bn, RSA_F4)){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "BN_set_word 'Unable set RSA_F4 to BIGNUM'");
		}

		if (keySize == NULL){
			keySize = 1024;
		}
		else{
			if (keySize < 1024){
				THROW_EXCEPTION(0, Key, NULL, "Key sizes should num > 1024 (else insecure)");
			}
		}

		LOGGER_OPENSSL(RSA_generate_key_ex);
		if (!RSA_generate_key_ex(rsa, keySize, bn, NULL)){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "RSA_generate_key_ex 'Unable  generates a key pair'");
		}

		LOGGER_OPENSSL(EVP_PKEY_set1_RSA);
		EVP_PKEY_set1_RSA(evpkey, rsa);

		LOGGER_OPENSSL(BIO_new);
		Handle<Bio> bp_private = new Bio(BIO_TYPE_MEM, data, "w+");
		if (bp_private.isEmpty()){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "new Bio BIO_TYPE_MEM 'Unable creates a new mem BIO'");
		}

		switch (format){
		case DataFormat::DER:
			if ((password).length() > 0){
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(bp_private->internal(), evpkey, EVP_aes_256_cbc(), (char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(bp_private->internal(), evpkey, NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		case DataFormat::BASE64:
			if ((password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(bp_private->internal(), evpkey, EVP_aes_256_cbc(), (unsigned char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(bp_private->internal(), evpkey, NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		ok = -1;
	}

	if (bp_private){
		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(bp_private);
	}

	if (rsa){
		LOGGER_OPENSSL(RSA_free);
		RSA_free(rsa);
	}

	if (bn){
		LOGGER_OPENSSL(BN_free)
			BN_free(bn);
	}

	if (evpkey){
		LOGGER_OPENSSL(EVP_PKEY_free);
		EVP_PKEY_free(evpkey);
	}

	return ok;
}

int Key::keypairGenerateBIO(Handle<Bio> bio, DataFormat::DATA_FORMAT format, int keySize, std::string password){
	LOGGER_FN();	

	int ok = 0;

	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
	EVP_PKEY *evpkey = NULL;

	try{
		ENGINE *en = NULL;

		LOGGER_OPENSSL(RSA_new_method);
		rsa = RSA_new_method(en);
		if (!rsa){
			THROW_EXCEPTION(0, Key, NULL, "RSA_new_method");
		}

		if (bio.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Parameter %d is NULL", 1);
		}

		LOGGER_OPENSSL(BN_new);
		bn = BN_new();
		if (!bn){
			THROW_EXCEPTION(0, Key, NULL, "BN_new");
		}

		LOGGER_OPENSSL(EVP_PKEY_new);
		evpkey = EVP_PKEY_new();
		if (!evpkey){
			THROW_EXCEPTION(0, Key, NULL, "EVP_PKEY_new");
		}

		LOGGER_OPENSSL(BN_set_word);
		if (!BN_set_word(bn, RSA_F4)){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "BN_set_word 'Unable set RSA_F4 to BIGNUM'");
		}

		if (keySize == NULL){
			keySize = 1024;
		}
		else{
			if (keySize < 1024){
				THROW_EXCEPTION(0, Key, NULL, "Key sizes should num > 1024 (else insecure)");
			}
		}

		LOGGER_OPENSSL(RSA_generate_key_ex);
		if (!RSA_generate_key_ex(rsa, keySize, bn, NULL)){
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "RSA_generate_key_ex 'Unable  generates a key pair'");
		}

		LOGGER_OPENSSL(EVP_PKEY_set1_RSA);
		EVP_PKEY_set1_RSA(evpkey, rsa);

		switch (format){
		case DataFormat::DER:
			if ((password).length() > 0){
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(bio->internal(), evpkey, EVP_aes_256_cbc(), (char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(bio->internal(), evpkey, NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		case DataFormat::BASE64:
			if ((password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(bio->internal(), evpkey, EVP_aes_256_cbc(), (unsigned char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(bio->internal(), evpkey, NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		ok = -1;
	}

	if (rsa){
		LOGGER_OPENSSL(RSA_free);
		RSA_free(rsa);
	}

	if (bn){
		LOGGER_OPENSSL(BN_free)
			BN_free(bn);
	}

	if (evpkey){
		LOGGER_OPENSSL(EVP_PKEY_free);
		EVP_PKEY_free(evpkey);
	}

	return ok;
}

int Key::privkeySave(std::string filename, DataFormat::DATA_FORMAT format, std::string password) {
	try{
		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "w+");
		EVP_PKEY *key = NULL;
		if (out.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		const void * pass = password.c_str();

		switch (format){
		case DataFormat::DER:
			if ((password).length() > 0){
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(out->internal(), this->internal(), EVP_aes_256_cbc(), (char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(out->internal(), this->internal(), NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		case DataFormat::BASE64:
			if ((password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(out->internal(), this->internal(), EVP_aes_256_cbc(), (unsigned char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(out->internal(), this->internal(), NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::privkeySaveBIO(Handle<Bio> out, DataFormat::DATA_FORMAT format, std::string password) {
	try{
		if (out.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		const void * pass = password.c_str();

		switch (format){
		case DataFormat::DER:
			if ((password).length() > 0){
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(out->internal(), this->internal(), EVP_aes_256_cbc(), (char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(out->internal(), this->internal(), NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		case DataFormat::BASE64:
			if ((password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(out->internal(), this->internal(), EVP_aes_256_cbc(), (unsigned char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(out->internal(), this->internal(), NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::privkeySaveMemory(std::string data, DataFormat::DATA_FORMAT format, std::string password) {
	try{
		Handle<Bio> out = new Bio(BIO_TYPE_MEM, data);

		const void * pass = password.c_str();

		switch (format){
		case DataFormat::DER:
			if ((password).length() > 0){
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(out->internal(), this->internal(), EVP_aes_256_cbc(), (char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(out->internal(), this->internal(), NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PKCS8PrivateKey_bio 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		case DataFormat::BASE64:
			if ((password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(out->internal(), this->internal(), EVP_aes_256_cbc(), (unsigned char *)((password).c_str()), (password).length(), NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			else{
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(out->internal(), this->internal(), NULL, NULL, 0, NULL, NULL)){
					THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PrivateKey 'Unable writes PrivateKey to BIO'");
				}
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::pubkeySave(std::string filename, DataFormat::DATA_FORMAT format) {
	try{
		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "w+");
		EVP_PKEY *key = NULL;
		if (out.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(i2d_PUBKEY_bio);
			if (!i2d_PUBKEY_bio(out->internal(), this->internal())){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PUBKEY_bio 'Unable writes PUBKEY to BIO'");
			}
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_write_bio_PUBKEY);
			if (!PEM_write_bio_PUBKEY(out->internal(), this->internal())){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PUBKEY 'Unable writes PUBKEY to BIO'");
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::pubkeySaveBIO(Handle<Bio> out, DataFormat::DATA_FORMAT format) {
	try{
		LOGGER_FN();

		if (out.isEmpty())
			THROW_EXCEPTION(0, Certificate, NULL, "Parameter %d is NULL", 1);	

		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(i2d_PUBKEY_bio);
			if (!i2d_PUBKEY_bio(out->internal(), this->internal())){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PUBKEY_bio 'Unable writes PUBKEY to BIO'");
			}
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_write_bio_PUBKEY);
			if (!PEM_write_bio_PUBKEY(out->internal(), this->internal())){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PUBKEY 'Unable writes PUBKEY to BIO'");
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

int Key::pubkeySaveMemory(std::string data, DataFormat::DATA_FORMAT format) {
	try{
		LOGGER_FN();

		Handle<Bio> out = new Bio(BIO_TYPE_MEM, data);

		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(i2d_PUBKEY_bio);
			if (!i2d_PUBKEY_bio(out->internal(), this->internal())){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "i2d_PUBKEY_bio 'Unable writes PUBKEY to BIO'");
			}
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_write_bio_PUBKEY);
			if (!PEM_write_bio_PUBKEY(out->internal(), this->internal())){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PUBKEY 'Unable writes PUBKEY to BIO'");
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, format);
		}
	}
	catch (Handle<Exception> e){
		return -1;
	}

	return 0;
}

bool Key::compare(Handle<Key> &key) {
	return EVP_PKEY_cmp(this->internal(), key->internal()) > 0 ? true : false;
}

void Key::read(Handle<Bio> in){
	if (in.isEmpty())
		THROW_EXCEPTION(0, Key, NULL, "Parameter %d cann't be NULL", 1);

	in->reset();
	EVP_PKEY *key = PEM_read_bio_PrivateKey(in->internal(), NULL, NULL, NULL);
	if (key) {
		this->type = KT_PRIVATE; //this->type = KeyType::PRIVATE;
	}
	else {
		key = d2i_PrivateKey_bio(in->internal(), NULL);
		if (key) {
			this->type = KT_PRIVATE; //this->type = KeyType::PRIVATE;
		}
	}

	if (!key)
		THROW_EXCEPTION(0, Key, NULL, "Error while reading data");

	this->setData(key);
}

Handle<Key> Key::duplicate(){
	Handle<Key> dkey = new Key(this->internal());
	CRYPTO_add(&this->internal()->references, 1, CRYPTO_LOCK_EVP_PKEY);
	return dkey;
}