#include "pe-packer/Structs.h"

void __declspec(naked) unpacker_main()
{
	__asm
	{
		push ebp;
		mov ebp, esp;
		sub esp, 128;
	}

	//... ������� ����� ...//

	//����� �������� ������
	unsigned int original_image_base;
	//������������� ����� ������ ������,
	//� ������� ��������� ������ ���������� ���
	//������������ � ���� ����������� ������
	unsigned int rva_of_first_section;

	//��� ���������� ����� ������ ��� ����, �����
	//�������� � ������� ������������ ������ �� ��������
	__asm
	{
		mov original_image_base, 0x11111111;
		mov rva_of_first_section, 0x22222222;
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
}