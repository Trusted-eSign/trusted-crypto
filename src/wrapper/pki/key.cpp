#include "../stdafx.h"

#include "key.h"

void Key::readPrivateKey(Handle<Bio> in, DataFormat::DATA_FORMAT format, Handle<std::string> password) {
	try{
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();

		EVP_PKEY *key = NULL;

		const void * pass = password->c_str();

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
			THROW_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Key, e, "Error read private key");
	}
}

void Key::readPublicKey(Handle<Bio> in, DataFormat::DATA_FORMAT format) {
	try{
		if (in.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		in->reset();

		EVP_PKEY *key = NULL;
		
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
			THROW_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data");
		}

		this->setData(key);
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Key, e, "Error read pubkey key");
	}
}

void Key::writePrivateKey(Handle<Bio> out, DataFormat::DATA_FORMAT format, Handle<std::string> password) {
	try{
		if (out.isEmpty()){
			THROW_EXCEPTION(0, Key, NULL, "Bio is empty");
		}

		switch (format){
		case DataFormat::DER:
			if (password->length() > 0){
				LOGGER_OPENSSL(i2d_PKCS8PrivateKey_bio);
				if (!i2d_PKCS8PrivateKey_bio(out->internal(), this->internal(), EVP_aes_256_cbc(), (char *)password->c_str(), password->length(), NULL, NULL)){
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
			if (password->length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
				if (!PEM_write_bio_PrivateKey(out->internal(), this->internal(), EVP_aes_256_cbc(), (unsigned char *)password->c_str(), password->length(), NULL, NULL)){
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
		THROW_EXCEPTION(0, Key, e, "Error write private key");
	}
}

void Key::writePublicKey(Handle<Bio> out, DataFormat::DATA_FORMAT format) {
	try{
		LOGGER_FN();

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
		THROW_EXCEPTION(0, Key, e, "Error write pubkey key to BIO");
	}
}

Handle<Key> Key::generate(DataFormat::DATA_FORMAT format, PublicExponent::Public_Exponent pubEx, int keySize) {
	LOGGER_FN();

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
	
		switch (pubEx){
		case PublicExponent::peRSA_3:
			LOGGER_OPENSSL(BN_set_word);
			if (!BN_set_word(bn, RSA_3)){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "BN_set_word 'Unable set RSA_3 to BIGNUM'");
			}
			break;
		case PublicExponent::peRSA_F4:
			LOGGER_OPENSSL(BN_set_word);
			if (!BN_set_word(bn, RSA_F4)){
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "BN_set_word 'Unable set RSA_F4 to BIGNUM'");
			}
			break;
		default:
			THROW_EXCEPTION(0, Key, NULL, "Unknown public exponent");
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

		return new Key(evpkey);
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Key, e, "Can not keypair generate and save to file");
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
}

int Key::compare(Handle<Key> key) {
	LOGGER_FN();

	LOGGER_OPENSSL(EVP_PKEY_cmp);
	return EVP_PKEY_cmp(this->internal(), key->internal());
}

Handle<Key> Key::duplicate(){
	Handle<Key> dkey = new Key(this->internal());
	CRYPTO_add(&this->internal()->references, 1, CRYPTO_LOCK_EVP_PKEY);
	return dkey;
}
