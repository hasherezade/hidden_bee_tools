#include <stdio.h>
#include <windows.h>
#include <peconv.h>

#include "rcx.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Args: <input RCX module>" << std::endl;
		system("pause");
		return -1;
	}
	size_t buf_size = 0;
	BYTE* buf = peconv::load_file(argv[1], buf_size);
	if (!buf) {
		std::cout << "Could not open the file!\n";
		return 0;
	}
	const size_t count = rcx_fs::enum_modules(buf, buf_size);
	if (count) {
		rcx_fs::dump_modules(buf, buf_size);
	}
	return count;
}
