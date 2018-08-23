#include <stdio.h>
#include <windows.h>

#include "bee.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Args: <bee module>" << std::endl;
		system("pause");
		return -1;
	}
	parse_bee(argv[1]);
	return 0;
}
