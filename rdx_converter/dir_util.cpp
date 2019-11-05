#include "dir_util.h"

std::string get_directory_name(IN const std::string str)
{
	size_t found = str.find_last_of("/\\");
	if (found == std::string::npos) {
		return str;
	}
	return str.substr(0, found);
}

std::string get_full_path(const char* szPath)
{
	char out_buf[MAX_PATH] = { 0 };
	if (GetFullPathNameA(szPath, MAX_PATH, out_buf, nullptr) == 0) {
		return "";
	}
	return out_buf;
}

bool dir_exists(const char* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool create_dir_recursively(std::string in_path)
{
	std::string path = get_full_path(in_path.c_str());
	if (path.length() == 0) path = in_path;

	if (dir_exists(path.c_str())) {
		return true;
	}
	size_t pos = 0;
	do
	{
		pos = path.find_first_of("\\/", pos + 1);
		if (CreateDirectoryA(path.substr(0, pos).c_str(), NULL) == FALSE) {
			if (GetLastError() != ERROR_ALREADY_EXISTS) {
				return false;
			}
		}
	} while (pos != std::string::npos);
	return true;
}
