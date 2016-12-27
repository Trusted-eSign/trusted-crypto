#ifndef UTIL_SLOT_INCLUDED
#define UTIL_SLOT_INCLUDED

#include "../common/common.h"

class Slot {
public:
	Slot(){};
	~Slot(){};

	Handle<std::string> findToken();
};

#endif //!UTIL_SLOT_INCLUDED 
