
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
//������������ ���� ���������� ��� ������ � PE-�������
#include <pe_lib/pe_bliss.h>

int main(int argc, char* argv[])
{
	//��������� �� �������������
	if (argc != 3)
	{
		std::cout << "Usage: unpacker_converter.exe unpacker.exe output.h" << std::endl;
		return 0;
	}

	//��������� ���� unpacker.exe - ��� ���
	//� ���� � ���� �������� � ������� argv �� ������� 1
	std::ifstream file(argv[1], std::ios::in | std::ios::binary);
	if (!file)
	{
		//���� ������� ���� �� ������� - ������� � ������ � �������
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		std::cout << "Creating unpacker source file..." << std::endl;

		//�������� ������� ���� ��� 32-������ PE-����
		//��������� ��� ��������� false, ������ ��� ��� �� �����
		//"�����" ������ ����������� �������� ����� � 
		//"�����" ������ ���������� ����������
		//��� �������� ��� �� ������������, ������� �� ��������� ��� ������
		pe_bliss::pe_base image = pe_bliss::pe_factory::create_pe(file, false);

		//�������� ������ ������ ������������
		pe_bliss::section_list& unpacker_sections = image.get_image_sections();
	
		
		//�������� ������ �� ������ ���� ������
		std::string& unpacker_section_data = unpacker_sections.at(0).get_raw_data();
		//������� ������� ����� � ����� ���� ������,
		//������� ���������� ������� ��� ������������
		int i;
		for (i = unpacker_section_data.size() - 1; i >= 0 && unpacker_section_data[i] == '\0'; --i)
		{}
		if (i != unpacker_section_data.size())
			unpacker_section_data.erase(i + 1);

		//��������� �������� ���� ��� ������ h-�����
		//��� ��� �������� � argv[2]
		std::ofstream output_source(argv[2], std::ios::out | std::ios::trunc);

		//�������� ����������� �������� ���
		output_source << std::hex << "#pragma once" << std::endl << "unsigned char unpacker_data[] = {";
		//������� ����� ��������� ������
		unsigned long len = 0;
		//����� ����� ������ ������
		std::string::size_type total_len = unpacker_section_data.length();

		//��� ������� ����� ������...
		for (std::string::const_iterator it = unpacker_section_data.begin(); it != unpacker_section_data.end(); ++it, ++len)
		{
			//��������� ����������� ��������, �����
			//������������ ��� ��� ��������
			if ((len % 16) == 0)
				output_source << std::endl;

			//���������� �������� �����
			output_source
				<< "0x" << std::setw(2) << std::setfill('0')
				<< static_cast<unsigned long>(static_cast<unsigned char>(*it));

			//�, ���� ����������, �������
			if (len != total_len - 1)
				output_source << ", ";
		}

		//����� ����
		output_source << " };" << std::endl;
	}
	catch (const pe_bliss::pe_exception& e)
	{
		//���� �� �����-�� ������� ������� ��� �� �������
		//������� ����� ������ � ������
		std::cout << e.what() << std::endl;
		return -1;
	}

	return 0;
}