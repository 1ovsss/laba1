#include <iostream>
#include <string>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <plusaes/plusaes.hpp>
#include <functional>

extern "C" {

	/* .bss has @nobits, so we need to force space allocation in elf file */
	unsigned char __attribute__((aligned(4096), section(".data"))) data11[4096];

	/* noiline to force compiler to not insert this function into main.
	 *
	 * Yes, yes, yes it is global, but clang is smart enough to inline and
	 * anyway leave this function
	 */
	unsigned long __attribute__((noinline)) compute(const char *str)
	{
		unsigned long hash;

		for (char c = *str; *str; str++)
			hash = ((hash << 5) + hash) + c;

		return hash;
	}
}

static void __attribute__((constructor)) disable_gdb(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 1, 0))
		exit(10);
}

static void decode(void)
{
	const std::vector<unsigned char> key = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
	const unsigned char iv[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	plusaes::Error e;

	if (mprotect((void *) (((unsigned long) &compute) & ~(4095)), 4096, PROT_EXEC | PROT_READ | PROT_WRITE)) {
		std::cout << "Failed to mprotect\n";
		exit(10);
	}

	e = plusaes::decrypt_cbc((const unsigned char *) &data11, 128, &key[0], key.size(), &iv, (unsigned char *) compute, 128, NULL);
	if (e) {
		std::cout << "error " << e << std::endl;
		exit(10);
	}
}

typedef unsigned long (*ff)(const char *);

int main(void)
{
	std::string input, input1;

	decode();

	std::cout << "Enter login: ";
	std::cin >> input;

	std::cout << "Enter password: ";
	std::cin >> input1;

	if (std::atoll(input1.c_str()) == compute(input.c_str()))
		std::cout << "Win\n";
	else
		std::cout << "Lose\n";
}
