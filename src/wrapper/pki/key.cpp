#include "stdafx.h"

#include <openssl/cms.h>
#include <openssl/err.h>

#include "key.h"

void Key::load(std::string filename) {
	Handle<Bio> in = new Bio(BIO_TYPE_FILE, filename, "rb");
	this->read(in);
}

Handle<Key> Key::publicKey() {
	if (this->type == KT_PRIVATE) { //this->type = KeyType::PRIVATE;
		EVP_PKEY *key = this->internal();
		EVP_PKEY *pubkey = NULL;

		int len = i2d_PublicKey(key, NULL);
		unsigned char *keyDer = new unsigned char[len + 1];
		unsigned char *p = keyDer;
		if (i2d_PublicKey(key, &p)) {
			unsigned char *p2 = keyDer;
			pubkey = d2i_PublicKey(key->type, &pubkey, (const unsigned char **) &p2, len);
		}
		delete keyDer;
		if (pubkey) {
			Handle<Key> res = new Key(pubkey);
			res->type = KT_PUBLIC; //res->type = KeyType::PUBLIC;
			return res;
		}
		throw 7;
	}
	throw 8;
}

Handle<Key> Key::generate() {
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx) {
		/* Error occurred */
		puts("1");
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		/* Error */
		puts("2");
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
		/* Error */
		puts("3");
	}
	/* Generate key */
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		/* Error */
		puts("4");
	}
	if (!pkey) {
		ERR_print_errors_fp(stdout);
		throw 5;
	}
	Handle<Key> res = new Key(pkey);
	res->type = KT_PRIVATE; //res->type = KeyType::PRIVATE;
	return res;
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