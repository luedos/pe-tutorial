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

	// File checking
#if true
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

	//��������, �� .NET �� ����� ��� ���������
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

#endif // File checking


	// Writing packed file info
#if true
	packed_file_info basic_info = { 0 };

	basic_info.number_of_sections = sections.size();

	//����� ������������ ���������� LOCK
	basic_info.lock_opcode = 0xf0;

	//���������� ������������� ����� � ������
	//������������ ������� ������� �������������� �����
	basic_info.original_import_directory_rva = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_IMPORT);
	basic_info.original_import_directory_size = image->get_directory_size(IMAGE_DIRECTORY_ENTRY_IMPORT);
	//���������� ��� ����� �����
	basic_info.original_entry_point = image->get_ep();
	//���������� ����� ����������� ������ ���� ������
	//�������������� �����
	basic_info.total_virtual_size_of_sections = image->get_size_of_image();


	//���������� ������������� ����� � ������
	//������������ ���������� �������� �������������� �����
	basic_info.original_resource_directory_rva = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	basic_info.original_resource_directory_size = image->get_directory_size(IMAGE_DIRECTORY_ENTRY_RESOURCE);

	//���������� ������������� ����� � ������
	//������������ ���������� ��������� �������������� �����
	basic_info.original_relocation_directory_rva = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	basic_info.original_relocation_directory_size = image->get_directory_size(IMAGE_DIRECTORY_ENTRY_BASERELOC);

	//���������� ������������� �����
	//������������ ���������� ������������ �������� �������������� �����
	basic_info.original_load_config_directory_rva = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);

#endif // Writing packed file info



	// Writing sections to the string 
	// (packed_setions_info [section's_info[], raw section's data])
#if true
	std::string packed_sections_info;
	{
		packed_sections_info.resize(sections.size() * sizeof(packed_section));

		std::string raw_section_data;

		unsigned long current_section = 0;

		//����������� ��� ������
		for (pe_bliss::section_list::const_iterator it = sections.begin(); it != sections.end(); ++it, ++current_section)
		{
			//������ �� ��������� ������
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
#endif // Writing sections to the string 


	
	pe_bliss::section new_section;

	new_section.set_name(".rsrc");

	new_section.readable(true).writeable(true).executable(true);

	// Compressing data
	// Adding too the begining of section file info:
	// Section [file_info, compressed_data]
#if true
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
#endif // Compressing data



	// GET TLS
	// "auto_ptr<tls_info> tls"
#if true
	//���� ���� ����� TLS, ������� ���������� � ���
	std::auto_ptr<pe_bliss::tls_info> tls;
	if (image->has_tls())
	{
		std::cout << "Reading TLS..." << std::endl;
		tls.reset(new pe_bliss::tls_info(pe_bliss::get_tls_info(*image)));
	}
#endif // GET TLS


	// GET EXPORTS (info and functions to export)
	// "exported_functions_list exports", "export_info exports_info"
#if true
	//���� ���� ����� ��������, ������� ���������� � ���
	//� �� ������
	pe_bliss::exported_functions_list exports;
	pe_bliss::export_info exports_info;
	if (image->has_exports())
	{
		std::cout << "Reading exports..." << std::endl;
		exports = pe_bliss::get_exported_functions(*image, exports_info);
	}
#endif // GET EXPORTS


	// GET LOAD CONFIG
	// "unique_ptr<image_config_info> load_config"
#if true

	std::unique_ptr<pe_bliss::image_config_info> load_config;
	if (image->has_config())
	{
		std::cout << "Reading Image Load Config..." << std::endl;

		try
		{
			load_config.reset(new pe_bliss::image_config_info(get_image_config(*image)));
		}
		catch (const pe_bliss::pe_exception& e)
		{
			image->remove_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
			std::cout << "Error reading load config directory: " << e.what() << std::endl;
		}
	}
	else
	{
		image->remove_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	}


#endif // GET LOAD CONFIG


	// GET RESOURCES
	// rewrite main resources (icon, manifest, version) to new resource dir
#if true
	//����� ������ �������� ���������� ��������
	pe_bliss::resource_directory new_root_dir;


	if (image->has_resources())
	{
		std::cout << "Repacking resources..." << std::endl;

		//������� ������� ��������� ����� (�������� ����������)
		pe_bliss::resource_directory root_dir = pe_bliss::get_resources(*image);

		//����������� ������������ � ����� ���������� ��������
		//�� ��������������� ������
		pe_bliss::pe_resource_viewer res(root_dir);
		pe_bliss::pe_resource_manager new_res(new_root_dir);

		try
		{
			//���������� ��� ����������� ������ ������
			//� ������ ������, ������� ID
			pe_bliss::pe_resource_viewer::resource_id_list icon_id_list(res.list_resource_ids(pe_bliss::pe_resource_viewer::resource_icon_group));
			pe_bliss::pe_resource_viewer::resource_name_list icon_name_list(res.list_resource_names(pe_bliss::pe_resource_viewer::resource_icon_group));
			//������� ������ ������������� ����������� �������, ������� ��������, ���� �� ���
			if (!icon_name_list.empty())
			{
				//������� ����� ������ ������ ��� ������ ������� ����� (�� ������� 0)
				//���� ���� ���� �� ����������� ����� ��� �������� ������, ����� ���� ������� list_resource_languages
				//���� ���� ���� �� �������� ������ ��� ����������� �����, ����� ���� ������� get_icon_by_name (���������� � ��������� �����)
				//������� ������ ������ � ����� ���������� ��������
				
				new_res.add_resource(
					res.get_resource_data_by_name(pe_bliss::pe_resource_viewer::resource_icon,icon_name_list[0]).get_data(),
					pe_bliss::pe_resource_viewer::resource_icon,
					icon_name_list[0], 
					res.list_resource_languages(pe_bliss::pe_resource_viewer::resource_icon_group, icon_name_list[0]).at(0));
			}
			else if (!icon_id_list.empty()) //���� ��� ����������� ����� ������, �� ���� ������ � ID
			{
				//������� ����� ������ ������ ��� ������ ������� ����� (�� ������� 0)
				//���� ���� ���� �� ����������� ����� ��� �������� ������, ����� ���� ������� list_resource_languages
				//���� ���� ���� �� �������� ������ ��� ����������� �����, ����� ���� ������� get_icon_by_id_lang
				//������� ������ ������ � ����� ���������� ��������
				new_res.add_resource(
					res.get_resource_data_by_id(pe_bliss::pe_resource_viewer::resource_icon, icon_id_list[0]).get_data(),
					pe_bliss::pe_resource_viewer::resource_icon,
					icon_id_list[0],
					res.list_resource_languages(pe_bliss::pe_resource_viewer::resource_icon_group, icon_id_list[0]).at(0));
			
			}
		}
		catch (const pe_bliss::pe_exception&)
		{
			//���� �����-�� ������ � ���������, ��������, ������ ���,
			//�� ������ �� ������
		}

		try
		{
			//������� ������ ����������, ������� ID
			pe_bliss::pe_resource_viewer::resource_id_list manifest_id_list(res.list_resource_ids(pe_bliss::pe_resource_viewer::resource_manifest));
			if (!manifest_id_list.empty()) //���� �������� ����
			{
				//������� ����� ������ �������� ��� ������ ������� ����� (�� ������� 0)
				//������� �������� � ����� ���������� ��������
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
			//���� �����-�� ������ � ���������,
			//�� ������ �� ������
		}

		try
		{
			//������� ������ �������� ���������� � ������, ������� ID
			pe_bliss::pe_resource_viewer::resource_id_list version_info_id_list(res.list_resource_ids(pe_bliss::pe_resource_viewer::resource_version));
			if (!version_info_id_list.empty()) //���� ���������� � ������ ����
			{
				//������� ����� ������ ��������� ���������� � ������ ��� ������ ������� ����� (�� ������� 0)
				//������� ���������� � ������ � ����� ���������� ��������
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
			//���� �����-�� ������ � ���������,
			//�� ������ �� ������
		}
	}

#endif // GET RESOURCES



	// Packed data section (resource section)
#if true
	{
		// Replacing all sections with one 
		// which we created earlier ("new_section")
		// (section has total virtual size)
#if true
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

#endif // Replacing all sections with one


		// Rebuilding imports
		// only two functions : "LoadLibraryA", "GetProcAddress"
		// addresses are in file_info
#if true
		std::cout << "Creating imports...\n";
		pe_bliss::import_library kernel32;
		kernel32.set_name("KERNEL32.dll");

		pe_bliss::imported_function func;
		func.set_name("LoadLibraryA");
		kernel32.add_import(func);

		//� ������ �������
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

		//���� � ��� ���� ������� ��� ������,
		//�������� �������������� �������� ������ �����
		//���������� � ��� ��������
		if (!new_root_dir.get_entry_list().empty())
			settings.enable_auto_strip_last_section(false);


		pe_bliss::rebuild_imports(*image, imports, added_section, settings);

#endif // Rebuilding imports


		//����������� �������, ���� ����, ��� ������������
		if (!new_root_dir.get_entry_list().empty())
			pe_bliss::rebuild_resources(*image, new_root_dir, added_section, added_section.get_raw_data().size());
		
		// Writing TLS data to file_info 
		// (which is allready in new_section)
#if true
		//���� � ����� ��� TLS
		if (tls.get())
		{
			//��������� �� ���� ��������� � �����������
			//��� ������������
			//��� ��������� � ����� ������ ���������������� ������,
			//�� �� ���� �������� ���� ������
			packed_file_info* info = reinterpret_cast<packed_file_info*>(&added_section.get_raw_data()[0]);

			//������� ������������� ����������� �����
			//������������� TLS
			info->original_tls_index_rva = tls->get_index_rva();

			//���� � ��� ���� TLS-��������, ������� � ���������
			//������������� ����������� ����� �� ������� � ������������ �����
			if (!tls->get_tls_callbacks().empty())
				info->original_rva_of_tls_callbacks = tls->get_callbacks_rva();

			//������ ������������� ����������� ����� ������� TLS
			//����� ������ - �� �������� ��������� �������� ��� � ���� tls_index
			//��������� packed_file_info
			tls->set_index_rva(image->rva_from_section_offset(added_section, offsetof(packed_file_info, tls_index)));
		}
#endif // Writing TLS data to file_info 
	} 
#endif // Packed data section



	// Unpacker section
#if true
	{

		// Adding unpacker section
		// Writing data (from unpacker.h)
		// replace some variables in data : 
		// ("original_image_base", "rva_of_first_section", "original_image_base_no_fixup")
#if true
		DWORD first_callback_offset = 0;

		pe_bliss::section unpacker_section;

		unpacker_section.set_name(".packed");

		unpacker_section.readable(true).executable(true).writeable(true);

		{
			//�������� ������ �� ������ ������ ������������
			std::string& unpacker_section_data = unpacker_section.get_raw_data();
			//���������� ���� ��� ������������
			//���� ��� �������� � �������������� �����
			//unpacker.h, ������� �� ���������� � main.cpp
			unpacker_section_data = std::string(reinterpret_cast<const char*>(unpacker_data), sizeof(unpacker_data));
			//���������� �� ������ ��������� �����
			//�������� ������
			*reinterpret_cast<DWORD*>(&unpacker_section_data[original_image_base_offset]) = image->get_image_base_32();
			//� ����������� ����� ����� ������ ������ ������������ �����,
			//� ������� ����� ������ ��� ���������� � ���������� � ���
			//� ����� ������ ��� ������, ��� �� �������, �����
			//��������� packed_file_info
			*reinterpret_cast<DWORD*>(&unpacker_section_data[rva_of_first_section_offset]) = image->get_image_sections().at(0).get_virtual_address();
		
			*reinterpret_cast<DWORD*>(&unpacker_section_data[original_image_base_no_fixup_offset]) = image->get_image_base_32();
		}

		//��������� � ��� ������
		pe_bliss::section& unpacker_added_section = image->add_section(unpacker_section);

#endif // Adding unpacker section 


		//������� ������ ������ ������ ������������ �����
		//�� ���������� ������ � ���� ������������
		//(�� ������, ���� ������� ����� � ����� ���� ��������
		//����������� ��� ������ � PE)
		if (tls.get() || image->has_exports() || image->has_reloc() || load_config.get())
		{
			//������� ������ ������ ������ ������������ �����
			//�� ���������� ������ � ���� ������������
			//(�� ������, ���� ������� ����� � ����� ���� ��������
			//����������� ��� ������ � PE)
			unpacker_added_section.get_raw_data().resize(sizeof(unpacker_data));
		}

		// Handling TLS
#if true
		//���� � ����� ���� TLS
		if (tls.get())
		{
			std::cout << "Rebuilding TLS..." << std::endl;

			//������ �� ����� ������ ������ ������������
			//������ ��� ���� ������ ���� ������������
			std::string& data = unpacker_added_section.get_raw_data();

			//�������� �������, � ������� ������� ��������� IMAGE_TLS_DIRECTORY32
			DWORD directory_pos = data.size();
			//������� ����� ��� ��� ���������
			//����� sizeof(DWORD) ����� ��� ������������, ��� ���
			//IMAGE_TLS_DIRECTORY32 ������ ���� ��������� 4-�������� �� �������
			data.resize(data.size() + sizeof(IMAGE_TLS_DIRECTORY32) + sizeof(DWORD));



			//���� � TLS ���� ��������...
			if (!tls->get_tls_callbacks().empty())
			{
				//���������� ��������������� �����
				//��� ������������ TLS-��������
				//���� 1 ������ ��� ������� DWORD
				first_callback_offset = data.size();
				data.resize(data.size() + sizeof(DWORD) * (tls->get_tls_callbacks().size() + 1));

				//������ ������� ����� ����� ������ (ret 0xC),
				//������� ��� �����
				*reinterpret_cast<DWORD*>(&data[first_callback_offset]) =
					image->rva_to_va_32(image->rva_from_section_offset(unpacker_added_section, unpacker_entry_point + empty_tls_callback_offset));

				//������� ������������� ����������� �����
				//����� ������� TLS-���������
				tls->set_callbacks_rva(image->rva_from_section_offset(unpacker_added_section, first_callback_offset));

				//������ ������� � ��������� packed_file_info, ������� ��
				//�������� � ����� ������ ������ ������,
				//������������� ����� ����� ������� ���������
				reinterpret_cast<packed_file_info*>(&image->get_image_sections().at(0).get_raw_data()[0])->new_rva_of_tls_callbacks = tls->get_callbacks_rva();
			}
			else
			{
				//���� ��� ���������, �� ������ ������ ������� �����
				tls->set_callbacks_rva(0);
			}

			//������� ������ ���������, ��� ��� ������ �� �����
			//�� �� ������� �������
			tls->clear_tls_callbacks();

			//��������� ����� ������������� �����
			//������ ��� ������������� ��������� ������ ������
			tls->set_raw_data_start_rva(image->rva_from_section_offset(unpacker_added_section, data.size()));
			//������������� ����� ����� ���� ������
			tls->recalc_raw_data_end_rva();

			//������������ TLS
			//��������� ������������, ��� �� ����� ������ ������ � ��������
			//�� ������� ��� ������� (�������� ��� ��������, ���� ����)
			//����� ���������, ��� �� ����� �������� ������� ����� � ����� ������
			pe_bliss::rebuild_tls(*image, *tls, unpacker_added_section, directory_pos, false, false, pe_bliss::tls_data_expand_raw, true, false);

			//��������� ������ ������� ��� �������������
			//��������� ������ ������
			unpacker_added_section.get_raw_data() += tls->get_raw_data();
			//������ ��������� ����������� ������ ������ "kaimi.io"
			//� ������ SizeOfZeroFill ���� TLS
			image->set_section_virtual_size(unpacker_added_section, data.size() + tls->get_size_of_zero_fill());
			//�������, ������� ��� �������� ������� ����� � ����� ������


			if (!image->has_reloc() && !image->has_exports() && !load_config.get())
			{
				std::string& unpacker_added_section_data = unpacker_added_section.get_raw_data();
				//������� ������� ����� � ����� ���� ������,
				//������� ���������� ������� ��� ������������
				int i;
				for (i = unpacker_added_section_data.size() - 1; i >= 0 && unpacker_added_section_data[i] == '\0'; --i)
				{
				}
				if (i != unpacker_added_section_data.size())
					unpacker_added_section_data.erase(i + 1);
			}


			//� ����������� �� ������� (���������� � �����������)
			image->prepare_section(unpacker_added_section);
		}
#endif // Handling TLS


		//���������� ����� ����� ����� - ������ ��� ���������
		//�� �����������, �� ����� ��� ������
		image->set_ep(image->rva_from_section_offset(unpacker_added_section, 0) + unpacker_entry_point);
	
		// Handling config 
#if true
		if (load_config.get())
		{
			std::cout << "Repacking load configuration..." << std::endl;

			pe_bliss::section& unpacker_section = image->get_image_sections().at(1);

			//������� ������� ������� LOCK-���������
			load_config->clear_lock_prefix_list();
			//������� ������������ ����� ������ ������ LOCK-��������
			load_config->add_lock_prefix_rva(image->rva_from_section_offset(image->get_image_sections().at(0), offsetof(packed_file_info, lock_opcode)));

			//������������ ���������� ������������ �������� � ����������� �� � ������ "kaimi.io"
			//������������ ������������� ������� SE Handler'�� � LOCK-���������
			pe_bliss::rebuild_image_config(*image, *load_config, unpacker_section, unpacker_section.get_raw_data().size(), true, true);
		}
#endif

		// Handling relocations
		// Adding to relocations original_image_base, which is in unpacker
		// Adding TLS functions
#if true
		//���� � ����� ���� ���������
		if (image->has_reloc())
		{
			std::cout << "Creating relocations..." << std::endl;

			//������� ������ ������ ��������� � ������������ �������
			pe_bliss::relocation_table_list reloc_tables;

			pe_bliss::section& unpacker_section = image->get_image_sections().at(1);


			{
				pe_bliss::relocation_table table;
				//������������� ����������� ����� ������� ���������
				//�� ����� ����� �������������� ������������ ������ ������ �����������
				//������, ��� ��� ������ � ��� ��������� ��� ������������
				//� ����������, ������� �� ����� �������
				table.set_rva(unpacker_section.get_virtual_address());

				//��������� ��������� �� �������� original_image_base_offset ��
				//����� parameters.h ������������
				table.add_relocation(pe_bliss::relocation_entry(original_image_base_offset, IMAGE_REL_BASED_HIGHLOW));
			}


			//���� � ����� ��� TLS
			if (tls.get())
			{
				//���������� �������� � ��������� TLS
				//������������ ������ ������ ������
				DWORD tls_directory_offset = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_TLS)
					- image->section_from_directory(IMAGE_DIRECTORY_ENTRY_TLS).get_virtual_address();

				//������� ����� ������� ���������, ��� ��� ������� � �������� TLS ����� ���� ������ �������
				//�� original_image_base_offset
				pe_bliss::relocation_table table;
				table.set_rva(image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_TLS));

				//������� ��������� ��� ����� StartAddressOfRawData,
				//EndAddressOfRawData � AddressOfIndex
				//��� ���� � ��� ������ ���������
				table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(tls_directory_offset + offsetof(IMAGE_TLS_DIRECTORY32, StartAddressOfRawData)), IMAGE_REL_BASED_HIGHLOW));
				table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(tls_directory_offset + offsetof(IMAGE_TLS_DIRECTORY32, EndAddressOfRawData)), IMAGE_REL_BASED_HIGHLOW));
				table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(tls_directory_offset + offsetof(IMAGE_TLS_DIRECTORY32, AddressOfIndex)), IMAGE_REL_BASED_HIGHLOW));

				//���� ������� TLS-��������
				if (first_callback_offset)
				{
					//�� ������� ��� ��������� ��� ���� AddressOfCallBacks
					//� ��� ������ ������ ������� ��������
					table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(tls_directory_offset + offsetof(IMAGE_TLS_DIRECTORY32, AddressOfCallBacks)), IMAGE_REL_BASED_HIGHLOW));
					table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(first_callback_offset), IMAGE_REL_BASED_HIGHLOW));
				}

				//��������� ������� � ������ ������
				reloc_tables.push_back(table);
			}

			if (load_config.get())
			{
				//���� ���� ����� IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, �� ������� �������� ����������� ��������� ��� ���,
				//������ ��� ��� ������������ ����������� �� ����� �������� PE-�����
				DWORD config_directory_offset = image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
					- image->section_from_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG).get_virtual_address();

				//������� ����� ������� ���������, ��� ��� ������� � �������� TLS ����� ���� ������ �������
				//�� original_image_base_offset ��� TLS
				pe_bliss::relocation_table table;
				table.set_rva(image->get_directory_rva(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));

				if (load_config->get_security_cookie_va())
					table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie)), IMAGE_REL_BASED_HIGHLOW));

				if (load_config->get_se_handler_table_va())
					table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerTable)), IMAGE_REL_BASED_HIGHLOW));

				table.add_relocation(pe_bliss::relocation_entry(static_cast<WORD>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, LockPrefixTable)), IMAGE_REL_BASED_HIGHLOW));
				reloc_tables.push_back(table);
			}


			

			//������������ ���������, ���������� �� � �����
			//������ � ����� ������������
			pe_bliss::rebuild_relocations(*image, reloc_tables, unpacker_section, unpacker_section.get_raw_data().size(), true, !image->has_exports() && !load_config.get());
		}

#endif // Handling relocations


		// Handling exports 
#if true
		if (image->has_exports())
		{
			std::cout << "Repacking exports..." << std::endl;

			pe_bliss::section& unpacker_section = image->get_image_sections().at(1);

			//������������ �������� � ����������� �� � ������ "kaimi.io"
			pe_bliss::rebuild_exports(*image, exports_info, exports, unpacker_section, unpacker_section.get_raw_data().size(), true, !load_config.get());
		}

		
#endif // Handling exports and config

	}
#endif // Unpacker section


	// Removing some directories (Bound import, IAT, Security, Debug)
#if true
	//������ ��� ����� ������������ ����������
	//� ���������� �� ����� �� ���������� �������
	//� ��������� ������������, �� ���� ���
	//������� ������ ������� (� ��, ������������ �� ���� �� �����)
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_IAT);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_SECURITY);
	image->remove_directory(IMAGE_DIRECTORY_ENTRY_DEBUG);

	//������� ���� �� ���������, ���� �����-�� ���
	image->strip_stub_overlay();
#endif // Removing some directories


	// Writing to file
#if true

	std::experimental::filesystem::path new_file_path = filePath;

	new_file_path.replace_extension();

	std::string name = new_file_path.filename().string() + "_packed.exe";

	new_file_path = filePath.parent_path();

	new_file_path.replace_filename(name);

	std::ofstream new_pe_file(new_file_path, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!new_pe_file)
	{
		//���� �� ������� ������� ���� - ������� ������
		std::cout << "Cannot create " << new_file_path.string() << std::endl;
		return false;
	}

	pe_bliss::rebuild_pe(*image, new_pe_file, false, false);

	std::cout << "File packed in \"" << new_file_path.filename().string() << '\"' << std::endl;

#endif // Writing to file

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

