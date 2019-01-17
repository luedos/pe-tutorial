
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
//Заголовочный файл библиотеки для работы с PE-файлами
#include <pe_lib/pe_bliss.h>

int main(int argc, char* argv[])
{
	//Подсказка по использованию
	if (argc != 3)
	{
		std::cout << "Usage: unpacker_converter.exe unpacker.exe output.h" << std::endl;
		return 0;
	}

	//Открываем файл unpacker.exe - его имя
	//и путь к нему хранятся в массиве argv по индексу 1
	std::ifstream file(argv[1], std::ios::in | std::ios::binary);
	if (!file)
	{
		//Если открыть файл не удалось - сообщим и выйдем с ошибкой
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		std::cout << "Creating unpacker source file..." << std::endl;

		//Пытаемся открыть файл как 32-битный PE-файл
		//Последние два аргумента false, потому что нам не нужны
		//"сырые" данные привязанных импортов файла и 
		//"сырые" данные отладочной информации
		//При упаковке они не используются, поэтому не загружаем эти данные
		pe_bliss::pe_base image = pe_bliss::pe_factory::create_pe(file, false);

		//Получаем список секций распаковщика
		pe_bliss::section_list& unpacker_sections = image.get_image_sections();
	
		
		//Получаем ссылку на данные этой секции
		std::string& unpacker_section_data = unpacker_sections.at(0).get_raw_data();
		//Удаляем нулевые байты в конце этой секции,
		//которые компилятор добавил для выравнивания
		int i;
		for (i = unpacker_section_data.size() - 1; i >= 0 && unpacker_section_data[i] == '\0'; --i)
		{}
		if (i != unpacker_section_data.size())
			unpacker_section_data.erase(i + 1);

		//Открываем выходной файл для записи h-файла
		//Его имя хранится в argv[2]
		std::ofstream output_source(argv[2], std::ios::out | std::ios::trunc);

		//Начинаем формировать исходный код
		output_source << std::hex << "#pragma once" << std::endl << "unsigned char unpacker_data[] = {";
		//Текущая длина считанных данных
		unsigned long len = 0;
		//Общая длина данных секции
		std::string::size_type total_len = unpacker_section_data.length();

		//Для каждого байта данных...
		for (std::string::const_iterator it = unpacker_section_data.begin(); it != unpacker_section_data.end(); ++it, ++len)
		{
			//Добавляем необходимые переносы, чтобы
			//получившийся код был читаемым
			if ((len % 16) == 0)
				output_source << std::endl;

			//Записываем значение байта
			output_source
				<< "0x" << std::setw(2) << std::setfill('0')
				<< static_cast<unsigned long>(static_cast<unsigned char>(*it));

			//И, если необходимо, запятую
			if (len != total_len - 1)
				output_source << ", ";
		}

		//Конец кода
		output_source << " };" << std::endl;
	}
	catch (const pe_bliss::pe_exception& e)
	{
		//Если по какой-то причине открыть его не удалось
		//Выведем текст ошибки и выйдем
		std::cout << e.what() << std::endl;
		return -1;
	}

	return 0;
}