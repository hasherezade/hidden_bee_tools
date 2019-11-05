#include <stdio.h>
#include <windows.h>
#include <peconv.h>


#include "rdx.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Args: <input RDX module>" << std::endl;
		system("pause");
		return -1;
	}
	size_t buf_size = 0;
	BYTE* buf = peconv::load_file(argv[1], buf_size);
	if (!buf) {
		std::cout << "Could not open the file!\n";
		return 0;
	}
	size_t count = rdx_fs::dump_modules(buf, buf_size);
	return count;
}
