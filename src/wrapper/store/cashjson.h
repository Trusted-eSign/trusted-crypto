#ifndef CASHJSON_H_INCLUDED
#define CASHJSON_H_INCLUDED

#include "../stdafx.h"

#include "../common/common.h"

#include "storehelper.h"

#include "../../jsoncpp/json/json.h"

class CashJson {
public:
	CashJson(Handle<std::string> fileName);
	~CashJson(){};

public:
	Handle<std::string> jsonFileName;

	Handle<PkiItemCollection> exportJson();
	void importJson(Handle<PkiItem> item);
};

#endif //CASHJSON_H_INCLUDED