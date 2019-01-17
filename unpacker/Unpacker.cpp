#include "pe-packer/Structs.h"

void __declspec(naked) unpacker_main()
{
	__asm
	{
		push ebp;
		mov ebp, esp;
		sub esp, 128;
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
}