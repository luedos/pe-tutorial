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

	DWORD total_virtual_size_of_sections; //Полный виртуальный размер всех секций оригинального файла
	DWORD original_import_directory_rva; //Относительный адрес оригинальной таблицы импорта
	DWORD original_import_directory_size; //Размер оригинальной таблицы импорта
	DWORD original_entry_point; //Оригинальная точка входа

	DWORD original_resource_directory_rva; //Относительный адрес оригинальной директории ресурсов
	DWORD original_resource_directory_size; //Размер оригинальной директории ресурсов

	//Сюда загрузчик будет записывать TLS-индекс
	DWORD tls_index;
	//Относительный адрес индекса TLS в оригинальном файле
	DWORD original_tls_index_rva;
	//Оригинальный адрес массива TLS-коллбэков в оригинальном файле
	DWORD original_rva_of_tls_callbacks;
	//Относительный адрес массива TLS-коллбэков в файле
	//после нашей модификации
	DWORD new_rva_of_tls_callbacks;


	DWORD original_relocation_directory_rva; //Относительный адрес оригинальной директории релокаций
	DWORD original_relocation_directory_size; //Размер оригинальной директории релокаций

	DWORD original_load_config_directory_rva; //Относительный адрес оригинальной директории конфигурации загрузки
	DWORD lock_opcode; //Фиктивный опкод команды ассемблера LOCK

	DWORD load_library_a;
	DWORD get_proc_address;
	DWORD end_of_import_address_table;
};
#pragma pack(pop)
