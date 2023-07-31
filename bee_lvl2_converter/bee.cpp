#include "bee.h"
#include <peconv.h>

BEE_TYPE check_type(BYTE *buf, size_t buf_size)
{
	if (memcmp(buf, &MAGIC2, sizeof(MAGIC2)) == 0) {
		return BEE_SCRAMBLED2;
	}
	if (memcmp(buf, &MAGIC1, sizeof(MAGIC1)) == 0) {
		return BEE_SCRAMBLED1;
	}
	if (memcmp(buf, &NS_MAGIC, sizeof(NS_MAGIC)) == 0) {
		return BEE_NS_FORMAT;
	}
	if (memcmp(buf, &RS_MAGIC, sizeof(RS_MAGIC)) == 0) {
		return RHADAM_RS_FORMAT;
	}
	if (memcmp(buf, &HS_MAGIC, sizeof(HS_MAGIC)) == 0) {
		return RHADAM_HS_FORMAT;
	}
	if (memcmp(buf, &XS_MAGIC, sizeof(XS_MAGIC)) == 0) {
		return RHADAM_XS_FORMAT;
	}
	return BEE_NONE;
}

template <typename T_BEE_SCRAMBLED>
bool unscramble_pe(BYTE *buf, size_t buf_size)
{
	T_BEE_SCRAMBLED *hdr = (T_BEE_SCRAMBLED*)buf;
	std::cout << std::hex 
		<< "Magic:     " << hdr->magic
		<< "\nMachineId: " << hdr->machine_id 
		<< "\nOffset:    " << hdr->pe_offset 
		<< std::endl;

	WORD *mz_ptr = (WORD*)buf;
	DWORD *pe_ptr = (DWORD*)(buf + hdr->pe_offset);

	*mz_ptr = IMAGE_DOS_SIGNATURE;
	*pe_ptr = IMAGE_NT_SIGNATURE;

	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)buf;
	dos_hdr->e_lfanew = hdr->pe_offset;

	IMAGE_FILE_HEADER* file_hdrs = const_cast<IMAGE_FILE_HEADER*>(peconv::get_file_hdr(buf, buf_size));
	if (!file_hdrs) return false;

	file_hdrs->Machine = hdr->machine_id;
	return true;
}

BLOB unscramble_bee_to_pe(BYTE *buf, size_t buf_size, bool is_mapped)
{
	BLOB mod = { 0 };
	BEE_TYPE type = check_type(buf, buf_size);
	if (type == BEE_NONE) {
		std::cout << "Unrecognized module!\n";
		return mod;
	}

	mod.pBlobData = buf;
	mod.cbSize = buf_size;
	
	std::cout << "Type: " << type << std::endl;
	switch (type) {
	case BEE_SCRAMBLED2:
		unscramble_pe<t_scrambled2>(buf, buf_size);
		break;
	case BEE_SCRAMBLED1:
		unscramble_pe<t_scrambled1>(buf, buf_size);
		break;
	case BEE_NS_FORMAT:
		ns_exe::unscramble_pe(buf, buf_size);
		break;
	case RHADAM_RS_FORMAT:
		mod = rs_exe::unscramble_pe(buf, buf_size, is_mapped);
		break;
	case RHADAM_HS_FORMAT:
		mod = hs_exe::unscramble_pe(buf, buf_size, is_mapped);
		break;
	case RHADAM_XS_FORMAT:
		mod = xs_exe::unscramble_pe(buf, buf_size, is_mapped);
		break;
	}
	return mod;
}
