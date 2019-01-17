#include "pch.h"

bool PackPE(const std::experimental::filesystem::path& filePath)
{



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

