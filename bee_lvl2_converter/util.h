#pragma once


inline DWORD gcd(DWORD a, DWORD b)
{
	while (b != 0) {
		DWORD t = b;
		b = a % b;
		a = t;
	}
	return a;
}
