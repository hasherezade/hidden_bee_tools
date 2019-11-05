#pragma once

#include <Windows.h>
#include <iostream>

std::string get_directory_name(IN const std::string str);

bool create_dir_recursively(std::string in_path);
