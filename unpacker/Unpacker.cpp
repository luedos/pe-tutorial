#include "pe-packer/Structs.h"

//Алгоритм распаковки
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

#define TEST_ false

	// post code
#if !TEST_
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




	//Обнулим всю память первой секции
 //эта область соответствует области памяти, которую
 //в оригинальном файле занимают все секции
	memset(
		reinterpret_cast<void*>(original_image_base + rva_of_first_section),
		0,
		total_virtual_size_of_sections - rva_of_first_section);

	//Изменим атрибуты блока памяти, в котором
	//расположены заголовки PE-файла и секций
	//Нам необходим доступ на запись
	DWORD old_protect;
	virtual_protect(reinterpret_cast<LPVOID>(offset_to_section_headers),
		number_of_sections * sizeof(IMAGE_SECTION_HEADER),
		PAGE_READWRITE, &old_protect);

	//Теперь изменим количество секций
	//в заголовке PE-файла на оригинальное
	file_header->NumberOfSections = number_of_sections;





	//Виртуальный адрес структуры заголовка секции
	DWORD current_section_structure_pos;
	current_section_structure_pos = offset_to_section_headers;
	//Перечислим все секции
	for (int i = 0; i != number_of_sections; ++i)
	{
		//Создаем структуру заголовка секции
		IMAGE_SECTION_HEADER section_header;
		//Обнуляем структуру
		memset(&section_header, 0, sizeof(section_header));
		//Заполняем важные поля:
		//Характеристики
		section_header.Characteristics = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->characteristics;
		//Смещение файловых данных
		section_header.PointerToRawData = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->pointer_to_raw_data;
		//Размер файловых данных
		section_header.SizeOfRawData = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->size_of_raw_data;
		//Относительный виртуальный адрес секции
		section_header.VirtualAddress = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->virtual_address;
		//Виртуальный размер секции
		section_header.Misc.VirtualSize = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->virtual_size;
		//Копируем оригинальное имя секции
		memcpy(section_header.Name, (reinterpret_cast<packed_section*>(unpacked_mem) + i)->name, sizeof(section_header.Name));

		//Копируем заполненный заголовок
		//в память, где находятся заголовки секций
		memcpy(reinterpret_cast<void*>(current_section_structure_pos), &section_header, sizeof(section_header));

		//Перемещаем указатель на следующий заголовок секции
		current_section_structure_pos += sizeof(section_header);
	}




	//Указатель на сырые данные секции
  //Необходим для разлепления сжатых данных секций
  //и распихивания их по нужным местам
	DWORD current_raw_data_ptr;
	current_raw_data_ptr = 0;
	//Восстановим указатель на заголовки секций
	current_section_structure_pos = offset_to_section_headers;
	//Снова перечисляем все секции
	for (int i = 0; i != number_of_sections; ++i)
	{
		//Заголовок секции, который мы только что сами записали
		const IMAGE_SECTION_HEADER* section_header = reinterpret_cast<const IMAGE_SECTION_HEADER*>(current_section_structure_pos);

		//Копируем данные секции в то место памяти,
		//где они должны располагаться
		memcpy(reinterpret_cast<void*>(original_image_base + section_header->VirtualAddress),
			reinterpret_cast<char*>(unpacked_mem) + number_of_sections * sizeof(packed_section) + current_raw_data_ptr,
			section_header->SizeOfRawData);

		//Перемещаем указатель на данные секции
		//в распакованном блоке данных
		current_raw_data_ptr += section_header->SizeOfRawData;

		//Переходим к следующему заголовку секции
		current_section_structure_pos += sizeof(IMAGE_SECTION_HEADER);
	}

	//Освобождаем память с распакованными данными,
	//она нам больше не нужна
	virtual_free(unpacked_mem, 0, MEM_RELEASE);



	//Вычислим относительный виртуальный адрес
  //начала таблицы директорий
	DWORD offset_to_directories;
	offset_to_directories = original_image_base + dos_header->e_lfanew
		+ sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	//Указатель на директорию импорта
	IMAGE_DATA_DIRECTORY* import_dir;
	import_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_IMPORT);
	//Записываем значения размера и виртуального адреса в соответствующие поля
	import_dir->Size = original_import_directory_size;
	import_dir->VirtualAddress = original_import_directory_rva;




	if (original_import_directory_rva)
	{
		//Виртуальный адрес первого дескриптора
		IMAGE_IMPORT_DESCRIPTOR* descr;
		descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(original_import_directory_rva + original_image_base);

		//Перечисляем все дескрипторы
		//Последний - нулевой
		while (descr->Name)
		{
			//Загружаем необходимую DLL
			HMODULE dll;
			dll = load_library_a(reinterpret_cast<char*>(descr->Name + original_image_base));
			//Указатели на таблицу адресов и lookup-таблицу
			DWORD* lookup, *address;
			//Учтем, что lookup-таблицы может и не быть,
			//как я говорил в предыдущем шаге
			lookup = reinterpret_cast<DWORD*>(original_image_base + (descr->OriginalFirstThunk ? descr->OriginalFirstThunk : descr->FirstThunk));
			address = reinterpret_cast<DWORD*>(descr->FirstThunk + original_image_base);

			//Перечисляем все импорты в дескрипторе
			while (true)
			{
				//До первого нулевого элемента в лукап-таблице
				DWORD lookup_value = *lookup;
				if (!lookup_value)
					break;

				//Проверим, импортируется ли функция по ординалу
				if (IMAGE_SNAP_BY_ORDINAL32(lookup_value))
					*address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value & ~IMAGE_ORDINAL_FLAG32)));
				else
					*address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value + original_image_base + sizeof(WORD))));

				//Переходим к следующему элементу
				++lookup;
				++address;
			}

			//Переходим к следующему дескриптору
			++descr;
		}
	}



	//Вернем атрибуты памяти заголовков, как было изначально
	virtual_protect(reinterpret_cast<LPVOID>(offset_to_section_headers), number_of_sections * sizeof(IMAGE_SECTION_HEADER), old_protect, &old_protect);

	//Эпилог вручную
	_asm
	{
		//Переходим на оригинальную точку входа
		mov eax, original_entry_point;
		add eax, original_image_base;
		leave;
		//Вот так
		jmp eax;
	}

#endif

	// Test code
#if TEST_
	
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



	_asm
	{
		leave;
		ret;
	}

	
#endif
}