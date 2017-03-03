#ifndef CMS_PKI_H_INCLUDED
#define  CMS_PKI_H_INCLUDED

#include "../common/common.h"

#define ERROR_DATA_FORMAT_UNKNOWN_FORMAT "Unknown data format using '%d'"

class DataFormat 
{
public:
	enum DATA_FORMAT {
		DER,
		BASE64
	};

	static DataFormat::DATA_FORMAT get(int value){
		switch (value){
		case DataFormat::DER:
			return DataFormat::DER;
		case DataFormat::BASE64:
			return DataFormat::BASE64;
		default:
			THROW_EXCEPTION(0, DataFormat, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, value);
		}
	}
};


#include "x509_name.h"
#include "alg.h"
#include "algs.h"
#include "attr.h"
#include "attr_vals.h"
#include "attrs.h"
#include "cert.h"
#include "certs.h"
#include "crl.h"
/*
#include "certs.h"
#include "key.h"
#include "oid.h"
*/

#endif //!CMS_CMS_H_INCLUDED
