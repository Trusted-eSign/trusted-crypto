/*#include "../stdafx.h"

#include "prov.h"

Provider::Provider()
{
	LOGGER_FN();

	_type = 0;
	_name = new std::string("");
}

Provider::Provider(const Provider &v){
	LOGGER_FN();

	_name = new std::string(v._name->c_str());
	_type = v._type;
}

Provider::~Provider()
{
	LOGGER_FN();
	
}

void Provider::name(char *v)
{
	LOGGER_FN();

	_name = new std::string(v);
}

Handle<std::string> Provider::name()
{
	LOGGER_FN();

	return _name;
}

void Provider::type(int v)
{
	LOGGER_FN();

	_type = v;
}

int Provider::type()
{
	LOGGER_FN();

	return _type;
}

ProviderCollection::ProviderCollection()
{
	LOGGER_FN();

	_items = std::vector <Provider>();
}

ProviderCollection::~ProviderCollection()
{
	LOGGER_FN();
}

Handle<Provider> ProviderCollection::items(int index)
{
	LOGGER_FN();

	return new Provider(_items.at(index));
}

int ProviderCollection::length()
{
	LOGGER_FN();

	return _items.size();
}

void ProviderCollection::push(Handle<Provider> v)
{
	LOGGER_FN();

	_items.push_back((*v.operator->()));
}

void ProviderCollection::push(Provider &v)
{
	LOGGER_FN();

	_items.push_back(v);
}
*/