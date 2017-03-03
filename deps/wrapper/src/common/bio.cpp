#include "../stdafx.h"

#include "wrapper/common/bio.h"

Bio::Bio(BIO *data, bool del)
{
	LOGGER_FN();
	
	this->init();

	this->data_ = data;
	this->delData_ = del;
}

Bio::Bio(int type, const std::string &data, const std::string &param)
{
	LOGGER_FN();

	init();

	switch (type){
	case BIO_TYPE_MEM:
		LOGGER_OPENSSL(BIO_new);
		this->data_ = BIO_new(BIO_s_mem());
		if (!this->data_)
			THROW_EXCEPTION(0, Bio, NULL, "BIO_new");
		this->write(data);
		break;
	case BIO_TYPE_FILE:
		LOGGER_OPENSSL(BIO_new_file);
		this->data_ = BIO_new_file(data.c_str(), param.c_str());
		if (!this->data_){
			//FILE *fp = NULL;
			//fp = fopen("ssl_err.txt", "w+");
			//ERR_print_errors_fp(fp);
			//fclose(fp);
			THROW_EXCEPTION(0, Bio, NULL, "BIO_new_file", BIO_CLOSE);
		}
		break;
	default:
		THROW_EXCEPTION(0, Bio, NULL, "Unknown type of BIO");
	}
}

Bio::~Bio()
{
	LOGGER_FN();

	if (this->delData_){		
		LOGGER_OPENSSL(BIO_free);
		BIO_free(this->data_);
	}
}

void Bio::init()
{
	LOGGER_FN();

	this->delData_ = true;
	this->data_ = NULL;
}

BIO *Bio::internal(){
	LOGGER_FN();

	return this->data_;
}

void Bio::write(const std::string&buf)
{
	LOGGER_FN();

	if (this->type() == BIO_TYPE_MEM){
		BIO_clear_flags(this->internal(), BIO_FLAGS_MEM_RDONLY);
	}

	BIO_write(this->data_, buf.c_str(), buf.length());
}

void Bio::write(Handle<std::string> buf)
{
	LOGGER_FN();

	if (this->type() == BIO_TYPE_MEM){
		BIO_clear_flags(this->internal(), BIO_FLAGS_MEM_RDONLY);
	}

	BIO_write(this->data_, buf->c_str(), buf->length());
}

Handle<std::string> Bio::read(int size)
{
	LOGGER_FN();

	if (this->type() == BIO_TYPE_MEM){
		BIO_set_flags(this->internal(), BIO_FLAGS_MEM_RDONLY);
	}

	std::string *res = new std::string("");
	int buf_size = size == -1 ? BIO_BUFFER_SIZE : size;
	for (;;){
		char *buf = (char *)OPENSSL_malloc(buf_size);
		//char *buf = NULL;
		//BIO_set_flags(this->data_, BIO_FLAGS_MEM_RDONLY);
		int buf_len = BIO_read(this->data_, buf, buf_size);
		//BIO_clear_flags(this->data_, BIO_FLAGS_MEM_RDONLY);
		if (buf_len <= 0){
			OPENSSL_free(buf);
			break;
		}
		*res += std::string(buf, buf_len);
		
		OPENSSL_free(buf);

		if (size >= 0) break;
	}
	return res;
}

void Bio::seek(int index){
	LOGGER_FN();

	if (BIO_seek(this->data_, index) < 0)
		THROW_EXCEPTION(1, Bio, NULL, "BIO_seek");
}

void Bio::reset(){
	LOGGER_FN();

	if (this->type() == BIO_TYPE_MEM)
		BIO_set_flags(this->internal(), BIO_FLAGS_MEM_RDONLY);
	if (BIO_reset(this->data_) < 0)
		THROW_EXCEPTION(1, Bio, NULL, "Reset");
}

int Bio::type(){
	LOGGER_FN();

	if (this->data_->method == NULL){
		THROW_EXCEPTION(0, Bio, NULL, "BIO.method is NULL");
	}
	return this->data_->method->type;
}

void Bio::flush(){
	LOGGER_FN();

	if (BIO_flush(this->internal()) < 0){
		THROW_EXCEPTION(0, Bio, NULL, "BIO_flush");
	}

}
