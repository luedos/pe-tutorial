#include "pch.h"

#include "Structs.h"
#include "unpacker/Parameters.h"

#include "unpacker/unpacker.h"

inline
size_t Align_down(size_t x, size_t align)
{
	return x < align ? x : x - (x % align);
}

inline
size_t Align_up(size_t x, size_t align)
{
	return x <= align ? align : x + align - (x % align);
}

bool PackPE(const std::experimental::filesystem::path& filePath)
{
	std::ifstream file(filePath, std::ios::in | std::ios::binary);
	if (!file)
	{
		std::cout << "Cannot open " << filePath.string() << std::endl;
		return false;
	}

	std::unique_ptr<pe_bliss::pe_base> image;
	
	try
	{
		image.reset(new pe_bliss::pe_base(pe_bliss::pe_factory::create_pe(file, false)));

		std::cout << "File OK\n";
	}
	catch (const pe_bliss::pe_exception& e)
	{
		std::cout << e.what() << std::endl;
		return false;
	}

	if (!image) 
	{
		std::cout << "Image value wasn't initialized" << std::endl;
		return false;
	}

	//Проверим, не .NET ли образ нам подсунули
	if (image->is_dotnet())
	{
		std::cout << ".NEt image cannot be packed!" << std::endl;
		return false;
	}

	{
		std::cout << "Entropy of sections: ";
		double entropy = pe_bliss::entropy_calculator::calculate_entropy(*image);
		
		std::cout << entropy << '\n';
		
		if (entropy > 6.8)
		{
			std::cout << "File has already been packed!" << std::endl;
			return false;
		}
	}

	if (lzo_init() != LZO_E_OK)
	{
		std::cout << "Error initializing LZO library" << std::endl;
		return false;
	}

	std::cout << "Reading sections..." << std::endl;

	const pe_bliss::section_list& sections = image->get_image_sections();

	if (sections.empty())
	{
		std::cout << "File has no sections!" << std::endl;
		return false;
	}


	packed_file_info basic_info = { 0 };

	basic_info.number_of_sections = sections.size();


	//Запоминаем относительный адрес и размер
	//оригинальной таблицы импорта упаковываемого файла
	basic_info.original_import_directory_rva = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_IMPORT);
	basic_info.original_import_directory_size = image->get_directory_size(IMAGE_DIRECTORY_ENTRY_IMPORT);
	//Запоминаем его точку входа
	basic_info.original_entry_point = image->get_ep();
	//Запоминаем общий виртуальный размер всех секций
	//упаковываемого файла
	basic_info.total_virtual_size_of_sections = image->get_size_of_image();


	//Запоминаем относительный адрес и размер
	//оригинальной директории ресурсов упаковываемого файла
	basic_info.original_resource_directory_rva = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	basic_info.original_resource_directory_size = image->get_directory_size(IMAGE_DIRECTORY_ENTRY_RESOURCE);



	std::string packed_sections_info;
	{
		packed_sections_info.resize(sections.size() * sizeof(packed_section));

		std::string raw_section_data;

		unsigned long current_section = 0;

		//Перечисляем все секции
		for (pe_bliss::section_list::const_iterator it = sections.begin(); it != sections.end(); ++it, ++current_section)
		{
			//Ссылка на очередную секцию
			const pe_bliss::section& s = *it;
			{
				packed_section& info
					= reinterpret_cast<packed_section&>(packed_sections_info[current_section * sizeof(packed_section)]);

				info.characteristics = s.get_characteristics();

				info.pointer_to_raw_data = s.get_pointer_to_raw_data();

				info.size_of_raw_data = s.get_size_of_raw_data();

				info.virtual_address = s.get_virtual_address();

				info.virtual_size = s.get_virtual_size();

				memset(info.name, 0, sizeof(info.name));
				memcpy(info.name, s.get_name().c_str(), s.get_name().length());
			}

			if (s.get_raw_data().empty())
				continue;

			raw_section_data += s.get_raw_data();
		}

		if (raw_section_data.empty())
		{
			std::cout << "All sections of PE file are empty!" << std::endl;
			return false;
		}

		packed_sections_info += raw_section_data;
	}

	pe_bliss::section new_section;

	new_section.set_name(".rsrc");

	new_section.readable(true).writeable(true).executable(true);

	std::string& out_buf = new_section.get_raw_data();

	{
		boost::scoped_array<lzo_align_t> work_memory(new lzo_align_t[LZO1Z_999_MEM_COMPRESS]);

		lzo_uint src_length = packed_sections_info.size();

		basic_info.size_of_unpacked_data = src_length;

		lzo_uint out_length = 0;

		out_buf.resize(src_length + src_length / 16 + 64 + 3);

		std::cout << "Packing data..." << std::endl;
		if (LZO_E_OK !=
			lzo1z_999_compress(reinterpret_cast<const unsigned char*>(packed_sections_info.data()),
				src_length,
				reinterpret_cast<unsigned char*>(&out_buf[0]),
				&out_length,
				work_memory.get())
			)
		{
			std::cout << "Error compressing data!" << std::endl;
			return false;
		}

		basic_info.size_of_packed_data = out_length;

		out_buf.resize(out_length);

		out_buf = std::string(reinterpret_cast<const char*>(&basic_info), sizeof(basic_info)) + out_buf;

		if (out_buf.size() >= src_length)
		{
			std::cout << "File is incompressible!" << std::endl;
			return false;
		}
	}

	std::cout << "Compressing succeed\n";

	//Если файл имеет TLS, получим информацию о нем
	std::auto_ptr<pe_bliss::tls_info> tls;
	if (image->has_tls())
	{
		std::cout << "Reading TLS..." << std::endl;
		tls.reset(new pe_bliss::tls_info(pe_bliss::get_tls_info(*image)));
	}


	//Удалим все часто используемые директории
	//В дальнейшем мы будем их возвращать обратно
	//и корректно обрабатывать, но пока так
	//Оставим только импорты (и то, обрабатывать их пока не будем)
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_IAT);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_SECURITY);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_DEBUG);

	//Урезаем таблицу директорий, удаляя все нулевые
	//Урезаем не полностью, а минимум до 12 элементов, так как в оригинальном
	//файле могут присутствовать первые 12 и использоваться
	//image->strip_data_directories(16 - 4);
	//Удаляем стаб из заголовка, если какой-то был
	image->strip_stub_overlay();





	//Новая пустая корневая директория ресурсов
	pe_bliss::resource_directory new_root_dir;


	if (image->has_resources())
	{
		std::cout << "Repacking resources..." << std::endl;

		//Получим ресурсы исходного файла (корневую директорию)
		pe_bliss::resource_directory root_dir = pe_bliss::get_resources(*image);

		//Оборачиваем оригинальную и новую директорию ресурсов
		//во вспомогательные классы
		pe_bliss::pe_resource_viewer res(root_dir);
		pe_bliss::pe_resource_manager new_res(new_root_dir);

		try
		{
			//Перечислим все именованные группы иконок
			//и группы иконок, имеющие ID
			pe_bliss::pe_resource_viewer::resource_id_list icon_id_list(res.list_resource_ids(pe_bliss::pe_resource_viewer::resource_icon_group));
			pe_bliss::pe_resource_viewer::resource_name_list icon_name_list(res.list_resource_names(pe_bliss::pe_resource_viewer::resource_icon_group));
			//Сначала всегда располагаются именованные ресурсы, поэтому проверим, есть ли они
			if (!icon_name_list.empty())
			{
				//Получим самую первую иконку для самого первого языка (по индексу 0)
				//Если надо было бы перечислить языки для заданной иконки, можно было вызвать list_resource_languages
				//Если надо было бы получить иконку для конкретного языка, можно было вызвать get_icon_by_name (перегрузка с указанием языка)
				//Добавим группу иконок в новую директорию ресурсов
				
				new_res.add_resource(
					res.get_resource_data_by_name(pe_bliss::pe_resource_viewer::resource_icon,icon_name_list[0]).get_data(),
					pe_bliss::pe_resource_viewer::resource_icon,
					icon_name_list[0], 
					res.list_resource_languages(pe_bliss::pe_resource_viewer::resource_icon_group, icon_name_list[0]).at(0));
			}
			else if (!icon_id_list.empty()) //Если нет именованных групп иконок, но есть группы с ID
			{
				//Получим самую первую иконку для самого первого языка (по индексу 0)
				//Если надо было бы перечислить языки для заданной иконки, можно было вызвать list_resource_languages
				//Если надо было бы получить иконку для конкретного языка, можно было вызвать get_icon_by_id_lang
				//Добавим группу иконок в новую директорию ресурсов
				new_res.add_resource(
					res.get_resource_data_by_id(pe_bliss::pe_resource_viewer::resource_icon, icon_id_list[0]).get_data(),
					pe_bliss::pe_resource_viewer::resource_icon,
					icon_id_list[0],
					res.list_resource_languages(pe_bliss::pe_resource_viewer::resource_icon_group, icon_id_list[0]).at(0));
			
			}
		}
		catch (const pe_bliss::pe_exception&)
		{
			//Если какая-то ошибка с ресурсами, например, иконок нет,
			//то ничего не делаем
		}

		try
		{
			//Получим список манифестов, имеющих ID
			pe_bliss::pe_resource_viewer::resource_id_list manifest_id_list(res.list_resource_ids(pe_bliss::pe_resource_viewer::resource_manifest));
			if (!manifest_id_list.empty()) //Если манифест есть
			{
				//Получим самый первый манифест для самого первого языка (по индексу 0)
				//Добавим манифест в новую директорию ресурсов
				new_res.add_resource(
					res.get_resource_data_by_id(pe_bliss::pe_resource_viewer::resource_manifest, manifest_id_list[0]).get_data(),
					pe_bliss::pe_resource_viewer::resource_manifest,
					manifest_id_list[0],
					res.list_resource_languages(pe_bliss::pe_resource_viewer::resource_manifest, manifest_id_list[0]).at(0)
				);
			}
		}
		catch (const pe_bliss::pe_exception&)
		{
			//Если какая-то ошибка с ресурсами,
			//то ничего не делаем
		}

		try
		{
			//Получим список структур информаций о версии, имеющих ID
			pe_bliss::pe_resource_viewer::resource_id_list version_info_id_list(res.list_resource_ids(pe_bliss::pe_resource_viewer::resource_version));
			if (!version_info_id_list.empty()) //Если информация о версии есть
			{
				//Получим самую первую структуру информации о версии для самого первого языка (по индексу 0)
				//Добавим информацию о версии в новую директорию ресурсов
				new_res.add_resource(
					res.get_resource_data_by_id(pe_bliss::pe_resource_viewer::resource_version, version_info_id_list[0]).get_data(),
					pe_bliss::pe_resource_viewer::resource_version,
					version_info_id_list[0],
					res.list_resource_languages(pe_bliss::pe_resource_viewer::resource_version, version_info_id_list[0]).at(0)
				);
			}
		}
		catch (const pe_bliss::pe_exception&)
		{
			//Если какая-то ошибка с ресурсами,
			//то ничего не делаем
		}
	}






	{
		const pe_bliss::section& first_section = image->get_image_sections().front();

		new_section.set_virtual_address(first_section.get_virtual_address());

		const pe_bliss::section& last_section = image->get_image_sections().back();

		DWORD total_virtual_size =
			last_section.get_virtual_address()
			+ Align_up(last_section.get_virtual_size(), image->get_section_alignment())
			- first_section.get_virtual_address();


		image->get_image_sections().clear();

		image->realign_file(0x200);

		pe_bliss::section& added_section = image->add_section(new_section);

		image->set_section_virtual_size(added_section, total_virtual_size);


		std::cout << "Creating imports...\n";
		pe_bliss::import_library kernel32;
		kernel32.set_name("KERNEL32.dll");

		pe_bliss::imported_function func;
		func.set_name("LoadLibraryA");
		kernel32.add_import(func);

		//И вторую функцию
		func.set_name("GetProcAddress");
		kernel32.add_import(func);

		DWORD load_library_address_rva =
			image->rva_from_section_offset(added_section, offsetof(packed_file_info, load_library_a));


		kernel32.set_rva_to_iat(load_library_address_rva);


		pe_bliss::imported_functions_list imports;

		imports.push_back(kernel32);

		pe_bliss::import_rebuilder_settings settings;

		settings.build_original_iat(false);

		settings.save_iat_and_original_iat_rvas(true, true);

		settings.set_offset_from_section_start(added_section.get_raw_data().size());

		//Если у нас есть ресурсы для сборки,
		//отключим автоматическое урезание секции после
		//добавления в нее импортов
		if (!new_root_dir.get_entry_list().empty())
			settings.enable_auto_strip_last_section(false);


		pe_bliss::rebuild_imports(*image, imports, added_section, settings);

		//Пересоберем ресурсы, если есть, что пересобирать
		if (!new_root_dir.get_entry_list().empty())
			pe_bliss::rebuild_resources(*image, new_root_dir, added_section, added_section.get_raw_data().size());
		
		

		//Если у файла был TLS
		if (tls.get())
		{
			//Указатель на нашу структуру с информацией
			//для распаковщика
			//Эта структура в самом начале свежедобавленной секции,
			//мы ее туда добавили чуть раньше
			packed_file_info* info = reinterpret_cast<packed_file_info*>(&added_section.get_raw_data()[0]);

			//Запишем относительный виртуальный адрес
			//оригинального TLS
			info->original_tls_index_rva = tls->get_index_rva();

			//Если у нас были TLS-коллбэки, запишем в структуру
			//относительный виртуальный адрес их массива в оригинальном файле
			if (!tls->get_tls_callbacks().empty())
				info->original_rva_of_tls_callbacks = tls->get_callbacks_rva();

			//Теперь относительный виртуальный адрес индекса TLS
			//будет другим - мы заставим загрузчик записать его в поле tls_index
			//структуры packed_file_info
			tls->set_index_rva(image->rva_from_section_offset(added_section, offsetof(packed_file_info, tls_index)));
		}

	}

	{
		pe_bliss::section unpacker_section;

		unpacker_section.set_name(".packed");

		unpacker_section.readable(true).executable(true).writeable(true);

		{
			//Получаем ссылку на данные секции распаковщика
			std::string& unpacker_section_data = unpacker_section.get_raw_data();
			//Записываем туда код распаковщика
			//Этот код хранится в автогенеренном файле
			//unpacker.h, который мы подключили в main.cpp
			unpacker_section_data = std::string(reinterpret_cast<const char*>(unpacker_data), sizeof(unpacker_data));
			//Записываем по нужным смещениям адрес
			//загрузки образа
			*reinterpret_cast<DWORD*>(&unpacker_section_data[original_image_base_offset]) = image->get_image_base_32();
			//и виртуальный адрес самой первой секции упакованного файла,
			//в которой лежат данные для распаковки и информация о них
			//В самом начале это секции, как вы помните, лежит
			//структура packed_file_info
			*reinterpret_cast<DWORD*>(&unpacker_section_data[rva_of_first_section_offset]) = image->get_image_sections().at(0).get_virtual_address();
		}

		//Добавляем и эту секцию
		pe_bliss::section& unpacker_added_section = image->add_section(unpacker_section);
		//Выставляем новую точку входа - теперь она указывает
		//на распаковщик, на самое его начало
		image->set_ep(image->rva_from_section_offset(unpacker_added_section, 0) + unpacker_entry_point);
	

		//Если у файла есть TLS
		if (tls.get())
		{
			std::cout << "Rebuilding TLS..." << std::endl;

			//Ссылка на сырые данные секции распаковщика
			//Сейчас там есть только тело распаковщика
			std::string& data = unpacker_added_section.get_raw_data();

			//Изменим размер данных секции распаковщика ровно
			//по количеству байтов в теле распаковщика
			//(на случай, если нулевые байты с конца были обрезаны
			//библиотекой для работы с PE)
			data.resize(sizeof(unpacker_data));

			//Вычислим позицию, в которую запишем структуру IMAGE_TLS_DIRECTORY32
			DWORD directory_pos = data.size();
			//Выделим место под эту структуру
			//запас sizeof(DWORD) нужен для выравнивания, так как
			//IMAGE_TLS_DIRECTORY32 должна быть выровнена 4-байтовую на границу
			data.resize(data.size() + sizeof(IMAGE_TLS_DIRECTORY32) + sizeof(DWORD));

			//Если у TLS есть коллбэки...
			if (!tls->get_tls_callbacks().empty())
			{
				//Необходимо зарезервировать место
				//под оригинальные TLS-коллбэки
				//Плюс 1 ячейка под нулевой DWORD
				DWORD first_callback_offset = data.size();
				data.resize(data.size() + sizeof(DWORD) * (tls->get_tls_callbacks().size() + 1));

				//Первый коллбэк будет нашим пустым (ret 0xC),
				//запишем его адрес
				*reinterpret_cast<DWORD*>(&data[first_callback_offset]) =
					image->rva_to_va_32(image->rva_from_section_offset(unpacker_added_section, unpacker_entry_point + empty_tls_callback_offset));

				//Запишем относительный виртуальный адрес
				//новой таблицы TLS-коллбэков
				tls->set_callbacks_rva(image->rva_from_section_offset(unpacker_added_section, first_callback_offset));

				//Теперь запишем в структуру packed_file_info, которую мы
				//записали в самое начало первой секции,
				//относительный адрес новой таблицы коллбэков
				reinterpret_cast<packed_file_info*>(&image->get_image_sections().at(0).get_raw_data()[0])->new_rva_of_tls_callbacks = tls->get_callbacks_rva();
			}
			else
			{
				//Если нет коллбэков, на всякий случай обнулим адрес
				tls->set_callbacks_rva(0);
			}

			//Очистим массив коллбэков, они нам больше не нужны
			//Мы их сделали вручную
			tls->clear_tls_callbacks();

			//Установим новый относительный адрес
			//данных для инициализации локальной памяти потока
			tls->set_raw_data_start_rva(image->rva_from_section_offset(unpacker_added_section, data.size()));
			//Пересчитываем адрес конца этих данных
			tls->recalc_raw_data_end_rva();

			//Пересобираем TLS
			//Указываем пересборщику, что не нужно писать данные и коллбэки
			//Мы сделаем это вручную (коллбэки уже записали, куда надо)
			//Также указываем, что не нужно обрезать нулевые байты в конце секции
			pe_bliss::rebuild_tls(*image,*tls, unpacker_added_section, directory_pos, false, false, pe_bliss::tls_data_expand_raw, true, false);

			//Дополняем секцию данными для инициализации
			//локальной памяти потока
			unpacker_added_section.get_raw_data() += tls->get_raw_data();
			//Теперь установим виртуальный размер секции "kaimi.io"
			//с учетом SizeOfZeroFill поля TLS
			image->set_section_virtual_size(unpacker_added_section, data.size() + tls->get_size_of_zero_fill());
			//Наконец, обрежем уже ненужные нулевые байты с конца секции


			std::string& unpacker_added_section_data = unpacker_added_section.get_raw_data();
			//Удаляем нулевые байты в конце этой секции,
			//которые компилятор добавил для выравнивания
			int i;
			for (i = unpacker_added_section_data.size() - 1; i >= 0 && unpacker_added_section_data[i] == '\0'; --i)
			{
			}
			if (i != unpacker_added_section_data.size())
				unpacker_added_section_data.erase(i + 1);

			//и пересчитаем ее размеры (физический и виртуальный)
			image->prepare_section(unpacker_added_section);
		}


	}










	std::experimental::filesystem::path new_file_path = filePath;

	new_file_path.replace_extension();

	std::string name = new_file_path.filename().string() + "_packed.exe";

	new_file_path = filePath.parent_path();

	new_file_path.replace_filename(name);

	std::ofstream new_pe_file(new_file_path, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!new_pe_file)
	{
		//Если не удалось создать файл - выведем ошибку
		std::cout << "Cannot create " << new_file_path.string() << std::endl;
		return false;
	}

	pe_bliss::rebuild_pe(*image, new_pe_file, false, false);

	std::cout << "File packed in \"" << new_file_path.filename().string() << '\"' << std::endl;

	return true;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cout << "Usage : pe-packer.exe <file to pack>" << std::endl;
		return 0;
	}

	PackPE(argv[1]);

	return 0;
}

