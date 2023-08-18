#pragma once

#include <windows.h>

namespace util {

	inline DWORD gcd(DWORD a, DWORD b)
	{
		while (b != 0) {
			DWORD t = b;
			b = a % b;
			a = t;
		}
		return a;
	}

	template <typename SECTION_T>
	DWORD calc_sec_alignment(SECTION_T* section, size_t sections_count, bool is_virtual = true)
	{
		DWORD prev = 0;
		for (size_t i = 0; i < sections_count; i++) {
			DWORD section_offst = is_virtual ? section[i].va : section[i].raw_addr;
			if (prev != 0) {
				prev = gcd(prev, section_offst);
			}
			else {
				prev = section_offst;
			}
		}
		return prev;
	}

	template <typename SECTION_T>
	DWORD get_first_section(SECTION_T* section, size_t sections_count, bool is_virtual = true)
	{
		DWORD min = 0;
		for (size_t i = 0; i < sections_count; i++) {
			DWORD section_offst = is_virtual ? section[i].va : section[i].raw_addr;
			if (min != 0) {
				min = min < section_offst ? min : section_offst;
			}
			else {
				min = section_offst;
			}
		}
		return min;
	}

};
