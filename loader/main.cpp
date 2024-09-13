#include <windows.h>
#include <iostream>

int main(int argc, char* argv[])
{
	if (argc < 2) {
		std::cout << "Arg <DLL path>\n";
	}
	
	HMODULE hMod = LoadLibraryA(argv[1]);
	if (!hMod) {
		std::cerr << "Loading DLL: " << argv[1] << " failed!\n";
		return -1;
	}
	std::cout << "Loaded at: " << std::hex << hMod << "\n";

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
	
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(dos->e_lfanew + (ULONG_PTR)hMod);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Verification failed!\n";
		return -1;
	}
	std::cout << "Entry Point: " << std::hex << nt->OptionalHeader.AddressOfEntryPoint << "\n";
	LPVOID*(*fetch_list)() = (LPVOID*(*)())(nt->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)hMod);
	LPVOID* functions = fetch_list();
	for (int i = 0; i < 3; i++) {
		std::cout << "Next: " << std::hex << functions[i] << "\n";
	}
	return 0;
}
