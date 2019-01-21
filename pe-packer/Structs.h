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

	DWORD total_virtual_size_of_sections; //������ ����������� ������ ���� ������ ������������� �����
	DWORD original_import_directory_rva; //������������� ����� ������������ ������� �������
	DWORD original_import_directory_size; //������ ������������ ������� �������
	DWORD original_entry_point; //������������ ����� �����

	DWORD original_resource_directory_rva; //������������� ����� ������������ ���������� ��������
	DWORD original_resource_directory_size; //������ ������������ ���������� ��������

	//���� ��������� ����� ���������� TLS-������
	DWORD tls_index;
	//������������� ����� ������� TLS � ������������ �����
	DWORD original_tls_index_rva;
	//������������ ����� ������� TLS-��������� � ������������ �����
	DWORD original_rva_of_tls_callbacks;
	//������������� ����� ������� TLS-��������� � �����
	//����� ����� �����������
	DWORD new_rva_of_tls_callbacks;


	DWORD original_relocation_directory_rva; //������������� ����� ������������ ���������� ���������
	DWORD original_relocation_directory_size; //������ ������������ ���������� ���������

	DWORD original_load_config_directory_rva; //������������� ����� ������������ ���������� ������������ ��������
	DWORD lock_opcode; //��������� ����� ������� ���������� LOCK

	DWORD load_library_a;
	DWORD get_proc_address;
	DWORD end_of_import_address_table;
};
#pragma pack(pop)
