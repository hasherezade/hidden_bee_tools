#include <stdio.h>
#include <windows.h>
#include <peconv.h>

#include "rcx.h"
#include "util.h"


BYTE *jpg_to_rcx(BYTE *buf, size_t buf_size)
{
	const size_t jpg_size = 10;
	unsigned char jpg_hdr[jpg_size] = {
		0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x18, 0x4A, 0x46, 0x49, 0x46
	};

	if (memcmp(buf, jpg_hdr, jpg_size) != 0) {
		return nullptr; // not a JPG
	}
	BYTE xor_key = buf[buf_size - 1];
	util::dexor(buf, buf_size, xor_key);

	BYTE* found = util::find_marker(buf, buf_size, RCX_MAGIC);
	return found;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Args: <RCX or JPG>" << std::endl;
		system("pause");
		return -1;
	}
	size_t buf_size = 0;
	size_t rcx_size = buf_size;
	BYTE* buf = peconv::load_file(argv[1], buf_size);
	if (!buf) {
		std::cout << "Could not open the file!\n";
		return 0;
	}
	BYTE *rcx_ptr = buf;
	if (*((DWORD*)buf) != RCX_MAGIC) {
		rcx_ptr = jpg_to_rcx(buf, buf_size);
		if (!rcx_ptr) return 0;

		rcx_size = buf_size - ((ULONG_PTR)rcx_ptr - (ULONG_PTR)buf);
		char* out_name = "decoded.rcx";
		if (peconv::dump_to_file(out_name, rcx_ptr, rcx_size)) {
			std::cout << "[*] Found RCX module in JPG, saved as: " << out_name << " \n";
		}
	}

	const size_t count = rcx_fs::enum_modules(rcx_ptr, rcx_size);
	if (count) {
		rcx_fs::dump_modules(rcx_ptr, rcx_size);
	}
	return count;
}
