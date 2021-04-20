#include "rcx.h"
#include <iostream>
#include <peconv.h>

#include "util.h"
#include <sstream>

#define _DECODE

using namespace rcx_fs;

BYTE *g_AESKey = NULL;

bool is_rcx(BYTE* buf, size_t buf_size)
{
	if (!buf || !buf_size) return false;
	const DWORD *magic = (DWORD*)buf;
	if (*magic != RCX_MAGIC) {
		std::cout << "[!] Magic number mismatch: " << std::hex << *magic << " vs: " << RCX_MAGIC << "\n";
		return false;
	}
	return true;
}

std::string translate_type(DWORD type)
{
	switch (type) {
	case RCX_PLAIN_SHELLCODE:
		return "plain: shellcode";
	case RCX_XOR_COMPRESSED_SHELLCODE32:
		return "XORed and compressed shellcode (32 bit)";
	case RCX_XOR_COMPRESSED_SHELLCODE64:
		return "XORed and compressed shellcode (64 bit)";
	case RCX_AES_KEY:
		return "AES key";
	case RCX_AES_LZMA_BLOB:
		return "AES encrypted & LZMA compressed RDX module";
	case RCX_PLAIN_URLS:
		return "plain: URLs";
	}
	return "Unknown";
}

size_t rcx_fs::enum_modules(BYTE* buf, size_t buf_size)
{
	if (!is_rcx(buf, buf_size)) return 0;

	rcx_struct *rcx_buf = (rcx_struct*) buf;
	size_t count = 0;

	std::cout << std::hex << "RCX size: " << rcx_buf->rcx_size << "\n\n";

	rcx_record *record = (rcx_record*)rcx_buf->records;
	while (record) {
		if (record->data_size == 0) {
			break;
		}
		std::cout << std::hex << "next: " << record->next_offset << "\n";
		std::cout << std::hex << "type: " << record->type  << " : " << translate_type (record->type) << "\n"
			<< "size: " << record->data_size << "\n"
			<< "out_size: " << record->output_size << "\n\n";

		count++;
		DWORD offset = record->next_offset;
		if (offset == 0 || offset > buf_size) break;
		
		record = (rcx_record*)(buf + offset);
	}
	return count;
}

std::string make_name(rcx_record *record, DWORD offset, char *extension)
{
	std::stringstream ss;
	ss << std::hex << record->type << "_" << offset << "." << extension;
	return ss.str();
}

bool decode_module(rcx_record *record, DWORD offset)
{
	if (record->type == RCX_XOR_COMPRESSED_SHELLCODE32 || record->type == RCX_XOR_COMPRESSED_SHELLCODE64) {
		util::dexor(record->data_buf, record->data_size, 0xE1);
		BYTE *out_buf = (BYTE *)malloc(record->output_size);
		int count = util::decompress(record->data_buf, record->data_size, out_buf, record->output_size);
		if (count != record->output_size) {
			std::cout << "Decompression failed, out: " << count << " vs " << record->output_size << "\n";
			free(out_buf);
			return false;
		}
		std::string name1 = make_name(record, offset, "dec");
		if (peconv::dump_to_file(name1.c_str(), out_buf, record->output_size)) {
			std::cout << "[*] Saved to: " << name1 << "\n";
			free(out_buf);
			return true;
		}
		free(out_buf);
	}
	if (record->type == RCX_AES_KEY && record->data_size == 16) {
		g_AESKey = record->data_buf;
	}
	if (record->type == RCX_AES_LZMA_BLOB && g_AESKey) {
		util::aes_decrypt(record->data_buf, record->data_size, g_AESKey);

		BYTE *out_buf = (BYTE *)malloc(record->output_size);
		int count = util::lzma_decompress(record->data_buf, record->data_size, out_buf, record->output_size);
		if (count != record->output_size) {
			std::cout << "LZMA Decompression failed, out: " << count << " vs " << record->output_size << "\n";
			free(out_buf);
			return false;
		}
		DWORD *rdx = (DWORD*)(out_buf);
		bool is_ok = (rdx && (*rdx == 'xdr!'));
		if (is_ok) {
			std::string name1 = make_name(record, offset, "rdx");
			if (peconv::dump_to_file(name1.c_str(), out_buf, record->output_size)) {
				std::cout << "[*] Saved to: " << name1 << "\n";
			}
		}
		free(out_buf);
		return is_ok;
	}
	return false;
}

size_t rcx_fs::dump_modules(BYTE* buf, size_t buf_size)
{
	if (!is_rcx(buf, buf_size)) return 0;

	rcx_struct *rcx_buf = (rcx_struct*)buf;
	size_t count = 0;

	rcx_record *record = (rcx_record*)rcx_buf->records;
	DWORD offset = FIELD_OFFSET(rcx_struct, records);
	while (record) {
		if (record->data_size == 0) {
			break;
		}

		std::string name1  = make_name(record, offset, "bin");
		if (peconv::dump_to_file(name1.c_str(), record->data_buf, record->data_size)) {
			std::cout << "[*] Saved to: " << name1 << "\n";
			count++;
		}
		
#ifdef _DECODE
		decode_module(record, offset);
#endif
		offset = record->next_offset;
		if (offset == 0 || offset > buf_size) break;

		record = (rcx_record*)(buf + offset);
	}
	return count;
}
