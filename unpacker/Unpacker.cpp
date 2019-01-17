#include "pe-packer/Structs.h"

//Алгоритм распаковки
#include "lzo_files/lzo_conf.h"
/* decompression */
LZO_EXTERN(int)
lzo1z_decompress(const lzo_bytep src, lzo_uint  src_len,
	lzo_bytep dst, lzo_uintp dst_len,
	lzo_voidp wrkmem /* NOT USED */);

void __declspec(naked) unpacker_main()
{
	__asm
	{
		push ebp;
		mov ebp, esp;
		sub esp, 256;
	}

	//... описано далее ...//

	//Адрес загрузки образа
	unsigned int original_image_base;
	//Относительный адрес первой секции,
	//в которую упаковщик кладет информацию для
	//распаковщика и сами упакованные данные
	unsigned int rva_of_first_section;

	//Эти инструкции нужны только для того, чтобы
	//заменить в билдере распаковщика адреса на реальные
	__asm
	{
		mov original_image_base, 0x11111111;
		mov rva_of_first_section, 0x22222222;
	}

	//Получаем указатель на структуру с информацией,
	//которую для нас заботливо приготовил упаковщик
	const packed_file_info* info;
	//Она находится в самом начале
	//первой секции упакованного файла
	info = reinterpret_cast<const packed_file_info*>(original_image_base + rva_of_first_section);

	//Два тайпдефа прототипов функций LoadLibraryA и GetProcAddress
	typedef HMODULE(__stdcall* load_library_a_func)(const char* library_name);
	typedef INT_PTR(__stdcall* get_proc_address_func)(HMODULE dll, const char* func_name);

	//Считаем их адреса из структуры packed_file_info
	//Их нам туда подложил загрузчик
	load_library_a_func load_library_a;
	get_proc_address_func get_proc_address;
	load_library_a = reinterpret_cast<load_library_a_func>(info->load_library_a);
	get_proc_address = reinterpret_cast<get_proc_address_func>(info->get_proc_address);


	//Создаем буфер на стеке
	char buf[32];

	//kernel32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'nrek';
	*reinterpret_cast<DWORD*>(&buf[4]) = '23le';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'lld.';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//Загружаем библиотеку kernel32.dll
	HMODULE kernel32_dll;
	kernel32_dll = load_library_a(buf);

	//Тайпдеф прототипа функции VirtualAlloc
	typedef LPVOID(__stdcall* virtual_alloc_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	//Тайпдеф прототипа функции VirtualProtect
	typedef LPVOID(__stdcall* virtual_protect_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	//Тайпдеф прототипа функции VirtualFree
	typedef LPVOID(__stdcall* virtual_free_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

	//VirtualAlloc
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Alau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'coll';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//Получаем адрес функции VirtualAlloc
	virtual_alloc_func virtual_alloc;
	virtual_alloc = reinterpret_cast<virtual_alloc_func>(get_proc_address(kernel32_dll, buf));

	//VirtualProtect
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Plau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'etor';
	*reinterpret_cast<DWORD*>(&buf[12]) = 'tc';

	//Получаем адрес функции VirtualProtect
	virtual_protect_func virtual_protect;
	virtual_protect = reinterpret_cast<virtual_protect_func>(get_proc_address(kernel32_dll, buf));

	//VirtualFree
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Flau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'eer';

	//Получаем адрес функции VirtualFree
	virtual_free_func virtual_free;
	virtual_free = reinterpret_cast<virtual_free_func>(get_proc_address(kernel32_dll, buf));


	//Относительный виртуальный адрес директории импорта
	DWORD original_import_directory_rva;
	//Виртуальный размер директории импорта
	DWORD original_import_directory_size;
	//Оригинальная точка входа
	DWORD original_entry_point;
	//Общий размер всех секций файла
	DWORD total_virtual_size_of_sections;
	//Количество секций в оригинальном файле
	BYTE number_of_sections;

	//Копируем эти значения из структуры packed_file_info,
	//которую для нас записал упаковщик
	original_import_directory_rva = info->original_import_directory_rva;
	original_import_directory_size = info->original_import_directory_size;
	original_entry_point = info->original_entry_point;
	total_virtual_size_of_sections = info->total_virtual_size_of_sections;
	number_of_sections = info->number_of_sections;



	//Указатель на память, в которую
	//мы запишем распакованные данные
	LPVOID unpacked_mem;
	//Выделяем память
	unpacked_mem = virtual_alloc(
		0,
		info->size_of_unpacked_data,
		MEM_COMMIT,
		PAGE_READWRITE);

	//Выходной размер распакованных данных
	//(эта переменная, в принципе, не нужна)
	lzo_uint out_len;
	out_len = 0;

	//Производим распаковку алгоритмом LZO
	lzo1z_decompress(
		reinterpret_cast<const unsigned char*>(reinterpret_cast<DWORD>(info) + sizeof(packed_file_info)),
		info->size_of_packed_data,
		reinterpret_cast<unsigned char*>(unpacked_mem),
		&out_len,
		0);




	//Указатель на DOS-заголовок файла
	const IMAGE_DOS_HEADER* dos_header;
	//Указатель на файловый заголовок
	IMAGE_FILE_HEADER* file_header;
	//Виртуальный адрес начала заголовков секций
	DWORD offset_to_section_headers;
	//Просчитываем этот адрес
	dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(original_image_base);
	file_header = reinterpret_cast<IMAGE_FILE_HEADER*>(original_image_base + dos_header->e_lfanew + sizeof(DWORD));
	//Вот по такой формуле
	offset_to_section_headers = original_image_base + dos_header->e_lfanew + file_header->SizeOfOptionalHeader
		+ sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;





	/*
	//user32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'resu';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'd.23';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'll';

	//Загружаем библиотеку user32.dll
	HMODULE user32_dll;
	user32_dll = load_library_a(buf);

	//Тайпдеф прототипа функции MessageBoxA
	typedef int(__stdcall* message_box_a_func)(HWND owner, const char* text, const char* caption, DWORD type);

	//MessageBoxA
	*reinterpret_cast<DWORD*>(&buf[0]) = 'sseM';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Bega';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'Axo';

	//Получаем адрес функции MessageBoxA
	message_box_a_func message_box_a;
	message_box_a = reinterpret_cast<message_box_a_func>(get_proc_address(user32_dll, buf));

	//Hello!
	*reinterpret_cast<DWORD*>(&buf[0]) = 'lleH';
	*reinterpret_cast<DWORD*>(&buf[4]) = '!!o';

	//Выводим месадж бокс
	message_box_a(0, buf, buf, MB_ICONINFORMATION);
	*/


	_asm
	{
		leave;
		ret;
	}
}