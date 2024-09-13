#include <windows.h>
#include <iostream>

struct view_port
{
	DWORD top;
	DWORD left;
	DWORD bottom;
	DWORD right;
};

void* __fastcall imgdat_init(char* dict);
bool __fastcall imgdat_process(void* init_stc, void* img_data, size_t img_size, view_port* view);
//---

BOOL dump_binary(LPSTR out_filename, void* pbData, size_t dwDataLen)
{
	FILE* fp = fopen(out_filename, "wb");
	if (fp == NULL) return FALSE;
	if (dwDataLen != 0) {
		fwrite(pbData, 1, dwDataLen, fp);
	}
	fclose(fp);
	return TRUE;
}


BYTE* read_binary(LPSTR filename, size_t &out_len)
{
	FILE* fp = fopen(filename, "rb");
	if (fp == NULL) return nullptr;

	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	BYTE* buf = (BYTE*) ::calloc(size, 1);
	fseek(fp, 0, SEEK_SET);
	if (buf) {
		out_len = fread(buf, 1, size, fp);
		std::cout << "Read size: " << std::dec << out_len << "\n";
	}
	fclose(fp);
	return buf;
}

int main(int argc, char* argv[])
{
	if (argc < 3) {
		std::cout << "Arg <DLL path> <image path>\n";
		return 0;
	}
	
	HMODULE hMod = LoadLibraryA(argv[1]);
	if (!hMod) {
		std::cerr << "Loading DLL: " << argv[1] << " failed!\n";
		return -1;
	}
	std::cout << "Loaded at: " << std::hex << hMod << "\n";
	size_t img_size = 0;
	BYTE* img_data = read_binary(argv[2], img_size);
	if (!img_data) {
		std::cerr << "Failed to load image!\n";
		return -1;
	}

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
	auto _imgdat_init = reinterpret_cast<decltype(&imgdat_init)>(functions[0]);
	char config[] = "Test";
	void* init_stc = _imgdat_init(config);

	std::cout << "Init: " << std::hex << init_stc << "\n";
	dump_binary("struct.bin", init_stc, 0x92B0);

	auto _imgdat_process = reinterpret_cast<decltype(&imgdat_process)>(functions[2]);
	view_port view;
	view.top = 0;
	view.left = 2;
	view.bottom = 0x1000;
	view.right = 0x2000;

	printf("Calling image processing!\n");
	BOOL res = _imgdat_process(init_stc, img_data, img_size, &view);
	std::cout << "RES: " << res << "\n";
	return 0;
}
