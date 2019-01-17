#pragma once
#include <Windows.h>

#pragma pack(1)
struct packed_section
{
	char name[8];
	DWORD virtual_size;
	DWORD virtual_address;
	DWORD size_of_raw_data;
	DWORD pointer_to_raw_data;
	DWORD characteristics;
};

struct packed_file_info
{
	BYTE number_of_sections;
	DWORD size_of_packed_data;
	DWORD size_of_unpacked_data;

	DWORD total_virtual_size_of_sections;
	DWORD original_import_directory_rva;
	DWORD original_import_directory_size;
	DWORD original_entry_point;

	DWORD load_library_a;
	DWORD get_proc_address;
	DWORD end_of_import_address_table;
};
#pragma pack(pop)
