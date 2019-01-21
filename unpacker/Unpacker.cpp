#include "pe-packer/Structs.h"

//�������� ����������
#include "lzo/lzoconf.h"
/* decompression */
LZO_EXTERN(int)
lzo1z_decompress(const lzo_bytep src, lzo_uint  src_len,
	lzo_bytep dst, lzo_uintp dst_len,
	lzo_voidp wrkmem /* NOT USED */);


void __declspec(naked) unpacker_main()
{
	__asm
	{
		jmp next;
		ret 0xC;
	next:

		push ebp;
		mov ebp, esp;
		sub esp, 2048;
	}

	//... ������� ����� ...//

	//����� �������� ������
	unsigned int original_image_base;
	//������������� ����� ������ ������,
	//� ������� ��������� ������ ���������� ���
	//������������ � ���� ����������� ������
	unsigned int rva_of_first_section;


	unsigned int original_image_base_no_fixup;
	//��� ���������� ����� ������ ��� ����, �����
	//�������� � ������� ������������ ������ �� ��������
	__asm
	{
		mov original_image_base, 0x11111111;
		mov rva_of_first_section, 0x22222222;
		mov original_image_base_no_fixup, 0x33333333;
	}

	//�������� ��������� �� ��������� � �����������,
	//������� ��� ��� ��������� ���������� ���������
	const packed_file_info* info;
	//��� ��������� � ����� ������
	//������ ������ ������������ �����
	info = reinterpret_cast<const packed_file_info*>(original_image_base + rva_of_first_section);

	//��� �������� ���������� ������� LoadLibraryA � GetProcAddress
	typedef HMODULE(__stdcall* load_library_a_func)(const char* library_name);
	typedef INT_PTR(__stdcall* get_proc_address_func)(HMODULE dll, const char* func_name);

	//������� �� ������ �� ��������� packed_file_info
	//�� ��� ���� �������� ���������
	load_library_a_func load_library_a;
	get_proc_address_func get_proc_address;
	load_library_a = reinterpret_cast<load_library_a_func>(info->load_library_a);
	get_proc_address = reinterpret_cast<get_proc_address_func>(info->get_proc_address);


	//������� ����� �� �����
	char buf[32];

#define TEST_ false

	// post code
#if !TEST_
	//kernel32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'nrek';
	*reinterpret_cast<DWORD*>(&buf[4]) = '23le';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'lld.';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//��������� ���������� kernel32.dll
	HMODULE kernel32_dll;
	kernel32_dll = load_library_a(buf);

	//������� ��������� ������� VirtualAlloc
	typedef LPVOID(__stdcall* virtual_alloc_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	//������� ��������� ������� VirtualProtect
	typedef LPVOID(__stdcall* virtual_protect_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	//������� ��������� ������� VirtualFree
	typedef LPVOID(__stdcall* virtual_free_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

	//VirtualAlloc
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Alau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'coll';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//�������� ����� ������� VirtualAlloc
	virtual_alloc_func virtual_alloc;
	virtual_alloc = reinterpret_cast<virtual_alloc_func>(get_proc_address(kernel32_dll, buf));

	//VirtualProtect
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Plau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'etor';
	*reinterpret_cast<DWORD*>(&buf[12]) = 'tc';

	//�������� ����� ������� VirtualProtect
	virtual_protect_func virtual_protect;
	virtual_protect = reinterpret_cast<virtual_protect_func>(get_proc_address(kernel32_dll, buf));

	//VirtualFree
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Flau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'eer';

	//�������� ����� ������� VirtualFree
	virtual_free_func virtual_free;
	virtual_free = reinterpret_cast<virtual_free_func>(get_proc_address(kernel32_dll, buf));




	////������������� ����������� ����� ���������� �������
	//DWORD original_import_directory_rva;
	////����������� ������ ���������� �������
	//DWORD original_import_directory_size;
	////������������ ����� �����
	//DWORD original_entry_point;
	////����� ������ ���� ������ �����
	//DWORD total_virtual_size_of_sections;
	////���������� ������ � ������������ �����
	//BYTE number_of_sections;
	//
	//
	//DWORD original_resource_directory_rva;
	////����������� ������ ���������� ��������
	//DWORD original_resource_directory_size;
	//
	//
	////�������� ��� �������� �� ��������� packed_file_info,
	////������� ��� ��� ������� ���������
	//original_import_directory_rva = info->original_import_directory_rva;
	//original_import_directory_size = info->original_import_directory_size;
	//original_entry_point = info->original_entry_point;
	//total_virtual_size_of_sections = info->total_virtual_size_of_sections;
	//number_of_sections = info->number_of_sections;
	//
	//original_resource_directory_rva = info->original_resource_directory_rva;
	//original_resource_directory_size = info->original_resource_directory_size;

	//�������� ��� ���� ��������� packed_file_info, ��� ��� ��� ��� �����
  //����� �����, �� ��������� �� ��������� info �� ����� ������
	packed_file_info info_copy;
	memcpy(&info_copy, info, sizeof(info_copy));


	//��������� �� ������, � �������
  //�� ������� ������������� ������
	LPVOID unpacked_mem;
	//�������� ������
	unpacked_mem = virtual_alloc(
		0,
		info->size_of_unpacked_data,
		MEM_COMMIT,
		PAGE_READWRITE);

	//�������� ������ ������������� ������
	//(��� ����������, � ��������, �� �����)
	lzo_uint out_len;
	out_len = 0;

	//���������� ���������� ���������� LZO
	lzo1z_decompress(
		reinterpret_cast<const unsigned char*>(reinterpret_cast<DWORD>(info) + sizeof(packed_file_info)),
		info->size_of_packed_data,
		reinterpret_cast<unsigned char*>(unpacked_mem),
		&out_len,
		0);


	//��������� �� DOS-��������� �����
	const IMAGE_DOS_HEADER* dos_header;
	//��������� �� �������� ���������
	IMAGE_FILE_HEADER* file_header;
	//����������� ����� ������ ���������� ������
	DWORD offset_to_section_headers;
	//������������ ���� �����
	dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(original_image_base);
	file_header = reinterpret_cast<IMAGE_FILE_HEADER*>(original_image_base + dos_header->e_lfanew + sizeof(DWORD));
	//��� �� ����� �������
	offset_to_section_headers = original_image_base + dos_header->e_lfanew + file_header->SizeOfOptionalHeader
		+ sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;




	//������� ��� ������ ������ ������
 //��� ������� ������������� ������� ������, �������
 //� ������������ ����� �������� ��� ������
	memset(
		reinterpret_cast<void*>(original_image_base + rva_of_first_section),
		0,
		info_copy.total_virtual_size_of_sections - rva_of_first_section);

	//������� �������� ����� ������, � �������
	//����������� ��������� PE-����� � ������
	//��� ��������� ������ �� ������
	DWORD old_protect;
	virtual_protect(reinterpret_cast<LPVOID>(offset_to_section_headers),
		info_copy.number_of_sections * sizeof(IMAGE_SECTION_HEADER),
		PAGE_READWRITE, &old_protect);

	//������ ������� ���������� ������
	//� ��������� PE-����� �� ������������
	file_header->NumberOfSections = info_copy.number_of_sections;





	//����������� ����� ��������� ��������� ������
	DWORD current_section_structure_pos;
	current_section_structure_pos = offset_to_section_headers;
	//���������� ��� ������
	for (int i = 0; i != info_copy.number_of_sections; ++i)
	{
		//������� ��������� ��������� ������
		IMAGE_SECTION_HEADER section_header;
		//�������� ���������
		memset(&section_header, 0, sizeof(section_header));
		//��������� ������ ����:
		//��������������
		section_header.Characteristics = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->characteristics;
		//�������� �������� ������
		section_header.PointerToRawData = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->pointer_to_raw_data;
		//������ �������� ������
		section_header.SizeOfRawData = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->size_of_raw_data;
		//������������� ����������� ����� ������
		section_header.VirtualAddress = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->virtual_address;
		//����������� ������ ������
		section_header.Misc.VirtualSize = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->virtual_size;
		//�������� ������������ ��� ������
		memcpy(section_header.Name, (reinterpret_cast<packed_section*>(unpacked_mem) + i)->name, sizeof(section_header.Name));

		//�������� ����������� ���������
		//� ������, ��� ��������� ��������� ������
		memcpy(reinterpret_cast<void*>(current_section_structure_pos), &section_header, sizeof(section_header));

		//���������� ��������� �� ��������� ��������� ������
		current_section_structure_pos += sizeof(section_header);
	}




	//��������� �� ����� ������ ������
  //��������� ��� ����������� ������ ������ ������
  //� ������������ �� �� ������ ������
	DWORD current_raw_data_ptr;
	current_raw_data_ptr = 0;
	//����������� ��������� �� ��������� ������
	current_section_structure_pos = offset_to_section_headers;
	//����� ����������� ��� ������
	for (int i = 0; i != info_copy.number_of_sections; ++i)
	{
		//��������� ������, ������� �� ������ ��� ���� ��������
		const IMAGE_SECTION_HEADER* section_header = reinterpret_cast<const IMAGE_SECTION_HEADER*>(current_section_structure_pos);

		//�������� ������ ������ � �� ����� ������,
		//��� ��� ������ �������������
		memcpy(reinterpret_cast<void*>(original_image_base + section_header->VirtualAddress),
			reinterpret_cast<char*>(unpacked_mem) + info_copy.number_of_sections * sizeof(packed_section) + current_raw_data_ptr,
			section_header->SizeOfRawData);

		//���������� ��������� �� ������ ������
		//� ������������� ����� ������
		current_raw_data_ptr += section_header->SizeOfRawData;

		//��������� � ���������� ��������� ������
		current_section_structure_pos += sizeof(IMAGE_SECTION_HEADER);
	}

	//����������� ������ � �������������� �������,
	//��� ��� ������ �� �����
	virtual_free(unpacked_mem, 0, MEM_RELEASE);



	//�������� ������������� ����������� �����
  //������ ������� ����������
	DWORD offset_to_directories;
	offset_to_directories = original_image_base + dos_header->e_lfanew
		+ sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	//��������� �� ���������� �������
	IMAGE_DATA_DIRECTORY* import_dir;
	import_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_IMPORT);
	//���������� �������� ������� � ������������ ������ � ��������������� ����
	import_dir->Size = info_copy.original_import_directory_size;
	import_dir->VirtualAddress = info_copy.original_import_directory_rva;


	//��������� �� ���������� ��������
	IMAGE_DATA_DIRECTORY* resource_dir;
	resource_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_RESOURCE);
	//���������� �������� ������� � ������������ ������ � ��������������� ����
	resource_dir->Size = info_copy.original_resource_directory_size;
	resource_dir->VirtualAddress = info_copy.original_resource_directory_rva;



	if (info_copy.original_import_directory_rva)
	{
		//����������� ����� ������� �����������
		IMAGE_IMPORT_DESCRIPTOR* descr;
		descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(info_copy.original_import_directory_rva + original_image_base);

		//����������� ��� �����������
		//��������� - �������
		while (descr->Name)
		{
			//��������� ����������� DLL
			HMODULE dll;
			dll = load_library_a(reinterpret_cast<char*>(descr->Name + original_image_base));
			//��������� �� ������� ������� � lookup-�������
			DWORD* lookup, *address;
			//�����, ��� lookup-������� ����� � �� ����,
			//��� � ������� � ���������� ����
			lookup = reinterpret_cast<DWORD*>(original_image_base + (descr->OriginalFirstThunk ? descr->OriginalFirstThunk : descr->FirstThunk));
			address = reinterpret_cast<DWORD*>(descr->FirstThunk + original_image_base);

			//����������� ��� ������� � �����������
			while (true)
			{
				//�� ������� �������� �������� � �����-�������
				DWORD lookup_value = *lookup;
				if (!lookup_value)
					break;

				//��������, ������������� �� ������� �� ��������
				if (IMAGE_SNAP_BY_ORDINAL32(lookup_value))
					*address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value & ~IMAGE_ORDINAL_FLAG32)));
				else
					*address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value + original_image_base + sizeof(WORD))));

				//��������� � ���������� ��������
				++lookup;
				++address;
			}

			//��������� � ���������� �����������
			++descr;
		}
	}





	//���� � ����� ���� ���������
	//� ���� ��� ��������� �����������
	if (info_copy.original_relocation_directory_rva
		&& original_image_base_no_fixup != original_image_base)
	{
		//��������� �� ������ ��������� IMAGE_BASE_RELOCATION
		const IMAGE_BASE_RELOCATION* reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(info_copy.original_relocation_directory_rva + original_image_base);

		//������ ���������� ������������ ��������� (���������)
		unsigned long reloc_size = info_copy.original_relocation_directory_size;
		//���������� ������������ ������ � ����������
		unsigned long read_size = 0;

		//����������� ������� ������������ ���������
		while (reloc->SizeOfBlock && read_size < reloc_size)
		{
			//����������� ��� �������� � �������
			for (unsigned long i = sizeof(IMAGE_BASE_RELOCATION); i < reloc->SizeOfBlock; i += sizeof(WORD))
			{
				//�������� ������������� ��������
				WORD elem = *reinterpret_cast<const WORD*>(reinterpret_cast<const char*>(reloc) + i);
				//���� ��� ��������� IMAGE_REL_BASED_HIGHLOW (������ �� ������ � PE x86)
				if ((elem >> 12) == IMAGE_REL_BASED_HIGHLOW)
				{
					//�������� DWORD �� ������ ���������
					DWORD* value = reinterpret_cast<DWORD*>(original_image_base + reloc->VirtualAddress + (elem & ((1 << 12) - 1)));
					//������ ���, ��� PE-���������
					*value = *value - original_image_base_no_fixup + original_image_base;
				}
			}

			//������������ ���������� ������������ ������
			//� ���������� ���������
			read_size += reloc->SizeOfBlock;
			//��������� � ��������� ������� ���������
			reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reinterpret_cast<const char*>(reloc) + reloc->SizeOfBlock);
		}
	}




	//��������� TLS-������
	if (info_copy.original_tls_index_rva)
		*reinterpret_cast<DWORD*>(info_copy.original_tls_index_rva + original_image_base) = info_copy.tls_index;

	if (info_copy.original_rva_of_tls_callbacks)
	{
		//���� TLS ����� ��������
		PIMAGE_TLS_CALLBACK* tls_callback_address;
		//��������� �� ������ ������� ������������� �������
		tls_callback_address = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.original_rva_of_tls_callbacks + original_image_base);
		//�������� ������������ ������ ������������� ������� TLS-���������
		DWORD offset = 0;

		while (true)
		{
			//���� ������� ������� - ��� ����� �������
			if (!*tls_callback_address)
				break;

			//��������� � ��� ������ ���������
			//����� �������������
			*reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.new_rva_of_tls_callbacks + original_image_base + offset) = *tls_callback_address;

			//�������� � ���������� ��������
			++tls_callback_address;
			offset += sizeof(DWORD);
		}

		//�������� �� ������ ��� ������ �������
		tls_callback_address = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.new_rva_of_tls_callbacks + original_image_base);
		while (true)
		{
			//���� ������� ������� - ��� ����� �������
			if (!*tls_callback_address)
				break;

			//������� �������
			(*tls_callback_address)(reinterpret_cast<PVOID>(original_image_base), DLL_PROCESS_ATTACH, 0);

			//�������� � ���������� ��������
			++tls_callback_address;
		}
	}






	//������ �������� ������ ����������, ��� ���� ����������
	virtual_protect(reinterpret_cast<LPVOID>(offset_to_section_headers), info_copy.number_of_sections * sizeof(IMAGE_SECTION_HEADER), old_protect, &old_protect);

	//������ �������
	_asm
	{
		//��������� �� ������������ ����� �����
		mov eax, info_copy.original_entry_point;
		add eax, original_image_base;
		leave;
		//��� ���
		jmp eax;
	}

#endif

	// Test code
#if TEST_
	
	//user32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'resu';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'd.23';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'll';

	//��������� ���������� user32.dll
	HMODULE user32_dll;
	user32_dll = load_library_a(buf);

	//������� ��������� ������� MessageBoxA
	typedef int(__stdcall* message_box_a_func)(HWND owner, const char* text, const char* caption, DWORD type);

	//MessageBoxA
	*reinterpret_cast<DWORD*>(&buf[0]) = 'sseM';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Bega';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'Axo';

	//�������� ����� ������� MessageBoxA
	message_box_a_func message_box_a;
	message_box_a = reinterpret_cast<message_box_a_func>(get_proc_address(user32_dll, buf));

	//Hello!
	*reinterpret_cast<DWORD*>(&buf[0]) = 'lleH';
	*reinterpret_cast<DWORD*>(&buf[4]) = '!!o';

	//������� ������ ����
	message_box_a(0, buf, buf, MB_ICONINFORMATION);



	_asm
	{
		leave;
		ret;
	}

	
#endif
}