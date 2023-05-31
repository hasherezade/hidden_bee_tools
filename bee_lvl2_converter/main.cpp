#include <stdio.h>
#include <windows.h>
#include <peconv.h>
#include <iostream>

#include "bee.h"

int main(int argc, char *argv[])
{
	if (argc < 3) {
		std::cout << "Args: <input bee module> <module base>" << std::endl;
		system("pause");
		return -1;
	}
	size_t buf_size = 0;
	BYTE* buf = peconv::load_file(argv[1], buf_size);
	if (!buf) {
		std::cout << "Could not open the file!\n";
		return 0;
	}
	BLOB out_mod = unscramble_bee_to_pe(buf, buf_size);
	if (!out_mod.pBlobData) {
		std::cout << "Failed to unscramble!\n";
		return -1;
	}
	peconv::dump_to_file("demo.bin", out_mod.pBlobData, out_mod.cbSize);
	peconv::t_pe_dump_mode dump_mode = peconv::PE_DUMP_AUTO;
	std::string out_path = std::string(argv[1]) + ".pe";
	ULONGLONG module_base = 0;
	if (sscanf(argv[2], "%llX", &module_base) == 0) {
		sscanf(argv[2], "%#llX", &module_base);
	}
	if (module_base == 0) {
		module_base = peconv::get_image_base(out_mod.pBlobData);
	}
	peconv::update_image_base(out_mod.pBlobData, module_base);
	if (peconv::dump_pe(out_path.c_str(), out_mod.pBlobData, out_mod.cbSize, module_base, dump_mode)) {
		std::cout << "[+] Converted to: " << out_path << std::endl;
		return 0;
	}
	std::cout << "[-] Conversion failed!" << std::endl;
	return -2;
}
