#include <elfio/elfio.hpp>
#include <plusaes/plusaes.hpp>
#include <vector>
#include <assert.h>

struct ElfSymbolData {
	ELFIO::Elf_Half section_index;
	ELFIO::Elf_Xword size;
	ELFIO::Elf64_Addr value;
};

static void find_symbol(const ELFIO::elfio &reader, std::string s_name, struct ElfSymbolData &data)
{
	ELFIO::Elf_Half sec_num = reader.sections.size();
	for (int i = 0; i < sec_num; ++i) {
		if (reader.sections[i]->get_type() == ELFIO::SHT_SYMTAB) {
			const ELFIO::symbol_section_accessor symbols(reader, reader.sections[i]);

			for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
				std::string name;
				unsigned char bind;
				unsigned char type;
				unsigned char other;

				symbols.get_symbol(j, name, data.value, data.size, bind, type, data.section_index, other);

				if (name == s_name) {
					std::cout << j << " " << name << std::endl;
					return;
				}
			}
		}
	}

	assert(0);
}

int main(int argc, char **argv)
{
	ELFIO::elfio reader;
	struct ElfSymbolData func, buffer;
	plusaes::Error e;

	if (!reader.load(argv[1])) {
		std::cout << "Can't find or process ELF file " << argv[1] << std::endl;
		return 2;
	}

	find_symbol(reader, std::move("compute"), func);

	const auto &sec = reader.sections[func.section_index];
	std::vector<unsigned char> data(sec->get_data() + func.value, sec->get_data() + func.value + func.size);

	const std::vector<unsigned char> key = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
	const unsigned char iv[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};

	std::vector<unsigned char> encrypted(plusaes::get_padded_encrypted_size(data.size()));
	e = plusaes::encrypt_cbc(data.data(), encrypted.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), false);
	if (e) {
		std::cout << "Failed to encrypt " << e << std::endl;
		return 4;
	}

	find_symbol(reader, "data11", buffer);

	const auto &sec1 = reader.sections[buffer.section_index];

	/* copy encoded function into buffer */
	memcpy(const_cast<char *>(sec1->get_data()) + buffer.value, (const char *) encrypted.data(), encrypted.size());

	/* zero out function */
	memset(const_cast<char *>(sec->get_data()) + func.value, 0x0, func.size);

	reader.save("main1.o");
}
