#include "../stdafx.h"

#include "wrapper/pki/key.h"

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
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data");
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
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "Can not read EVP_PKEY data");
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

Handle<Key> Key::generate(Handle<std::string> algorithm, std::vector<std::string> pkeyopt) {
	LOGGER_FN();

	try {
		EVP_PKEY *pkey = NULL;
		EVP_PKEY_CTX *ctx = NULL;
		const EVP_PKEY_ASN1_METHOD *ameth;
		ENGINE *tmpeng = NULL;
		int pkey_id;

		if (algorithm.isEmpty() || !algorithm->length()) {
			THROW_EXCEPTION(0, Key, NULL, "Parameter algorithm empty");
		}

		LOGGER_OPENSSL(EVP_PKEY_asn1_find_str);
		if (!(ameth = EVP_PKEY_asn1_find_str(&tmpeng, algorithm->c_str(), -1))) {
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "EVP_PKEY_asn1_find_str 'Algorithm not found'");
		}

		LOGGER_OPENSSL(EVP_PKEY_asn1_get0_info);
		EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
		if (tmpeng) {
			LOGGER_OPENSSL(ENGINE_finish);
			ENGINE_finish(tmpeng);
		}
#endif
		if (!(ctx = EVP_PKEY_CTX_new_id(pkey_id, NULL))) {
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "EVP_PKEY_CTX_new_id for %d", pkey_id);
		}

		if (!ctx) {
			THROW_EXCEPTION(0, Key, NULL, "Can not keypair generate");
		}

		LOGGER_OPENSSL(EVP_PKEY_keygen_init);
		if (EVP_PKEY_keygen_init(ctx) <= 0) {
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "EVP_PKEY_keygen_init");
		}

		for (size_t i = 0; i < pkeyopt.size(); i++) {
			const char *value = pkeyopt[i].c_str();
			char *stmp, *vtmp = NULL;

			stmp = BUF_strdup(value);
			if (!stmp)
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "BUF_strdup");
			vtmp = strchr(stmp, ':');
			if (vtmp) {
				*vtmp = 0;
				vtmp++;
			}
			
			LOGGER_OPENSSL(EVP_PKEY_CTX_ctrl_str);
			if (EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp) <= 0) {
				THROW_OPENSSL_EXCEPTION(0, Key, NULL, "parameter setting error");
			}
		}

		LOGGER_OPENSSL(EVP_PKEY_keygen);
		if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
			THROW_OPENSSL_EXCEPTION(0, Key, NULL, "Error generating key");
		}

		if (ctx) {
			LOGGER_OPENSSL(EVP_PKEY_CTX_free);
			EVP_PKEY_CTX_free(ctx);
		}

		return new Key(pkey);
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Key, e, "Can not keypair generate");
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
