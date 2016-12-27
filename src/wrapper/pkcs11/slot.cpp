#include "../stdafx.h"

#include "slot.h"

Handle<std::string> Slot::findToken() {
	LOGGER_FN();

	try {
		THROW_EXCEPTION(0, Slot, NULL, "Unsupported function");
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Slot, e, "Error find token");
	}
}
