#pragma once

#include <Windows.h>
#include <iostream>

namespace util {
	BYTE* dexor(BYTE *buf, size_t buf_size, BYTE key);
};
