#include "../stdafx.h"

#include "cipher.h"

Cipher::Cipher(Handle<std::string> ñipherAlgorithm){
	LOGGER_FN();

	if (ñipherAlgorithm.isEmpty()){
		THROW_EXCEPTION(0, Cipher, NULL, "Cipher algorithm null");
	}

	try{
		/*Cipher by name*/
		LOGGER_OPENSSL(EVP_get_cipherbyname);
		if ((cipher = EVP_get_cipherbyname(ñipherAlgorithm->c_str())) == NULL){
			THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "EVP_get_cipherbyname 'return NULL'");
		}

		/*Default digest*/
		LOGGER_OPENSSL(EVP_sha256);
		if ((dgst = EVP_sha256()) == NULL){
			THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "Digest undefined");
		} 

		/*Rand salt*/
		LOGGER_OPENSSL(RAND_pseudo_bytes);
		if (RAND_pseudo_bytes(salt, sizeof salt) < 0){
			THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "Invalid generate pseudo rand");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Cipher, e, "Error init cipher");
	}
}

void Cipher::encrypt(Handle<Bio> inSource, Handle<Bio> outEnc){
	LOGGER_FN();

	try{
		/*Check pass*/
		if (hpass == NULL){

			/*Check key*/
			if (hkey == NULL){
				THROW_EXCEPTION(0, Cipher, NULL, "key  undefined");
			}

			/*Check IV*/
			if (hiv == NULL){
				THROW_EXCEPTION(0, Cipher, NULL, "iv undefined");
			}
		}
		
		if((buff = (unsigned char *)OPENSSL_malloc(EVP_ENCODE_LENGTH(bsize))) == NULL){
			THROW_EXCEPTION(0, Cipher, NULL, "OPENSSL_malloc failure");
		}

		/*
		* We use 'benc' how cipher BIO method.
		* This is a filter BIO that encrypts any data written through it
		*/
		LOGGER_OPENSSL(BIO_new);
		if ((benc = BIO_new(BIO_f_cipher())) == NULL){
			THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "BIO_new(BIO_f_cipher())");
		}

		/*Save internal BIO cipher context to 'ctx'*/
		LOGGER_OPENSSL(BIO_get_cipher_ctx);
		BIO_get_cipher_ctx(benc, &ctx);

		/*Use param '1' for encrypt*/
		LOGGER_OPENSSL(EVP_CipherInit_ex);
		if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)) {
			THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "Error setting cipher");
		}

		wbio = outEnc->internal();
		
		/*
		* Write 'Salted__' and salt to bio.
		* Without salt possible to perform  dictionary attacks on the password
		*/
		if (hpass){
			LOGGER_OPENSSL(BIO_write);
			if ((BIO_write(wbio, magic, sizeof magic - 1) != sizeof magic - 1
				|| BIO_write(wbio, (char *)salt, sizeof salt) != sizeof salt)){
				THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "Error write bio");
			}
		}		

		if (benc != NULL){
			LOGGER_OPENSSL(BIO_push);
			wbio = BIO_push(benc, wbio);
		}

		/*Write data to bio (cipher BIO method)*/
		for (;;) {
			LOGGER_OPENSSL(BIO_read);
			inl = BIO_read(inSource->internal(), (char *)buff, bsize);
			if (inl <= 0){
				break;
			}
			LOGGER_OPENSSL(BIO_write);
			if (BIO_write(wbio, (char *)buff, inl) != inl) {
				THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "Error writing output bio");
			}
		}

		LOGGER_OPENSSL(BIO_flush);
		if (!BIO_flush(wbio)){
			THROW_EXCEPTION(0, Cipher, NULL, "bad decrypt");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Cipher, e, "Error encrypt");
	}	
}

void Cipher::decrypt(Handle<Bio> inEnc, Handle<Bio> outDec){
	LOGGER_FN();

	try{
		/*Check pass*/
		if (hpass == NULL){

			/*Check key*/
			if (hkey == NULL){
				THROW_EXCEPTION(0, Cipher, NULL, "key  undefined");
			}

			/*Check IV*/
			if (hiv == NULL){
				THROW_EXCEPTION(0, Cipher, NULL, "iv undefined");
			}
		}

		if ((buff = (unsigned char *)OPENSSL_malloc(EVP_ENCODE_LENGTH(bsize))) == NULL){
			THROW_EXCEPTION(0, Cipher, NULL, "OPENSSL_malloc failure");
		}

		rbio = inEnc->internal();
		wbio = outDec->internal();

		/*Read salt from encrypted file. Need for generate key and iv*/
		if (hpass){
			LOGGER_OPENSSL(BIO_read);
			if (BIO_read(rbio, mbuf, sizeof mbuf) != sizeof mbuf || BIO_read(rbio, (unsigned char *)salt, sizeof salt) != sizeof salt){
				THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "error reading input file");
			}
			else if (memcmp(mbuf, magic, sizeof magic - 1)) {
				THROW_EXCEPTION(0, Cipher, NULL, "bad magic number");
			}

			if (!hkey){
				LOGGER_OPENSSL(EVP_BytesToKey);
				if (EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)hpass, strlen(hpass), 1, key, NULL) == 0){
					THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "EVP_BytesToKey");
				}
			}
			else if (!hiv){
				LOGGER_OPENSSL(EVP_BytesToKey);
				if (EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)hpass, strlen(hpass), 1, NULL, iv) == 0){
					THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "EVP_BytesToKey");
				}
			}
			else if (!hkey && !hiv){
				LOGGER_OPENSSL(EVP_BytesToKey);
				if (EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)hpass, strlen(hpass), 1, key, iv) == 0){
					THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "EVP_BytesToKey");
				}
			}
		}		

		LOGGER_OPENSSL(BIO_new);
		if ((benc = BIO_new(BIO_f_cipher())) == NULL){
			THROW_EXCEPTION(0, Cipher, NULL, "BIO_new(BIO_f_cipher())");
		}

		LOGGER_OPENSSL(BIO_get_cipher_ctx);
		BIO_get_cipher_ctx(benc, &ctx);

		/*Use param '0' for decrypt*/
		LOGGER_OPENSSL(EVP_CipherInit_ex);
		if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0)) {
			THROW_EXCEPTION(0, Cipher, NULL, "Error setting cipher");
		}

		if (benc != NULL){
			LOGGER_OPENSSL(BIO_push);
			wbio = BIO_push(benc, wbio);
		}

		/*Write data to bio (cipher BIO method)*/
		for (;;) {
			LOGGER_OPENSSL(BIO_read);
			inl = BIO_read(rbio, (char *)buff, bsize);
			if (inl <= 0){
				break;
			}
			LOGGER_OPENSSL(BIO_write);
			if (BIO_write(wbio, (char *)buff, inl) != inl) {
				THROW_EXCEPTION(0, Cipher, NULL, "Error writing output bio");
			}
		}

		LOGGER_OPENSSL(BIO_flush);
		if (!BIO_flush(wbio)){
			THROW_EXCEPTION(0, Cipher, NULL, "bad decrypt");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Cipher, e, "Error decrypt");
	}
}

void Cipher::setDigest(Handle<std::string> md){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(EVP_get_digestbyname);
		if (md->length() && (dgst = EVP_get_digestbyname(md->c_str())) == NULL){
			THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "Error digest name");
		}		
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Cipher, e, "Error set digest");
	}
	
}

void Cipher::setPass(Handle<std::string> password){
	LOGGER_FN();

	if (password.isEmpty()) {
		THROW_EXCEPTION(0, Cipher, NULL, "Password cannot be empty");
	}
	else{
		hpass = strdup(password->c_str());
	}

	LOGGER_OPENSSL(EVP_BytesToKey);
	if (EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)hpass, strlen(hpass), 1, key, iv) == 0){
		THROW_OPENSSL_EXCEPTION(0, Cipher, NULL, "EVP_BytesToKey");
	}
}

void Cipher::setSalt(Handle<std::string> saltP){
	LOGGER_FN();

	try{
		if (saltP->length() <= 16) {
			hsalt = strdup(saltP->c_str());
		}
		else{
			THROW_EXCEPTION(0, Cipher, NULL, "Salt must be no more 16 characters");
		}

		if (hsalt) {
			if (!setHex(hsalt, salt, sizeof salt)) {
				THROW_EXCEPTION(0, Cipher, NULL, "Invalid hex salt value");
			}
		}
		else{
			THROW_EXCEPTION(0, Cipher, NULL, "Salt cannot be null");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Cipher, e, "Error set salt");
	}
}

void Cipher::setIV(Handle<std::string> ivP){
	LOGGER_FN();

	try{
		hiv = strdup(ivP->c_str());

		if (hiv != NULL){
			LOGGER_OPENSSL(EVP_CIPHER_iv_length);
			int siz = EVP_CIPHER_iv_length(cipher);
			if (siz == 0) {
				THROW_EXCEPTION(0, Cipher, NULL, "iv not use by this cipher");
			}
			else if (!setHex(hiv, iv, sizeof iv)) {
				THROW_EXCEPTION(0, Cipher, NULL, "Invalid hex iv value");
			}
		}
		if ((hiv == NULL) && EVP_CIPHER_iv_length(cipher) != 0) {
			THROW_EXCEPTION(0, Cipher, NULL, "iv undefined");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Cipher, e, "Error set iv");
	}
}

void Cipher::setKey(Handle<std::string> keyP){
	LOGGER_FN();

	try{
		hkey = strdup(keyP->c_str());

		if (hkey == NULL) {
			THROW_EXCEPTION(0, Cipher, NULL, "key undefined");
		}
		if ((hkey != NULL) && !setHex(hkey, key, EVP_CIPHER_key_length(cipher))) {
			THROW_EXCEPTION(0, Cipher, NULL, "Invalid hex key value");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Cipher, e, "Error set key");
	}
}

int Cipher::setHex(char *in, unsigned char *out, int size){
	LOGGER_FN();

	int i, n;
	unsigned char j;

	n = strlen(in);
	if (n > (size * 2)) {
		THROW_EXCEPTION(0, Cipher, NULL, "hex string is too long");
	}
	memset(out, 0, size);
	for (i = 0; i < n; i++) {
		j = (unsigned char)*in;
		*(in++) = '\0';
		if (j == 0)
			break;
		if ((j >= '0') && (j <= '9'))
			j -= '0';
		else if ((j >= 'A') && (j <= 'F'))
			j = j - 'A' + 10;
		else if ((j >= 'a') && (j <= 'f'))
			j = j - 'a' + 10;
		else {
			THROW_EXCEPTION(0, Cipher, NULL, "non-hex digit");
		}
		if (i & 1)
			out[i / 2] |= j;
		else
			out[i / 2] = (j << 4);
	}
	return (1);
}

Handle<std::string> Cipher::getSalt(){
	LOGGER_FN();

	if (salt){
		Handle<std::string> res = new std::string(reinterpret_cast<char*>(salt));
		return res;
	}
	else{
		return NULL;
	}
}

Handle<std::string> Cipher::getIV(){
	LOGGER_FN();

	if (iv){
		Handle<std::string> res = new std::string(reinterpret_cast<char*>(iv));
		return res;
	}
	else{
		return NULL;
	}
}

Handle<std::string> Cipher::getKey(){
	LOGGER_FN();

	if (iv){
		Handle<std::string> res = new std::string(reinterpret_cast<char*>(key));
		return res;
	}
	else{
		return NULL;
	}
}

Handle<std::string> Cipher::getAlgorithm(){
	LOGGER_FN();
	
	if (cipher){
		Handle<std::string> res = new std::string(EVP_CIPHER_name(cipher));
		return res;
	}
	else{
		return NULL;
	}
}

Handle<std::string> Cipher::getMode(){
	LOGGER_FN();

	if (cipher){
		std::string temp;
		if (EVP_CIPH_ECB_MODE == EVP_CIPHER_mode(cipher)){
			temp = "ecb";
		}
		else if (EVP_CIPH_CBC_MODE == EVP_CIPHER_mode(cipher)){
			temp = "cbc";
		}
		else if (EVP_CIPH_CFB_MODE == EVP_CIPHER_mode(cipher)){
			temp = "cfb";
		}
		else if (EVP_CIPH_OFB_MODE == EVP_CIPHER_mode(cipher)){
			temp == "ofb";
		}

		Handle<std::string> res = new std::string(temp);

		return res;
	}
	else{
		return NULL;
	}
}

Handle<std::string> Cipher::getDigestAlgorithm(){
	LOGGER_FN();

	if (dgst){
		Handle<std::string> res = new std::string(EVP_MD_name(dgst));
		return res;
	}
	else{
		return NULL;
	}
}