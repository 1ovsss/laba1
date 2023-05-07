#include <iostream>
#include <string>
#include <functional>

unsigned long __attribute__((noinline)) compute(const char *str)
	{
		unsigned long hash;

                for (char c = *str; *str; str++)
                        hash = ((hash << 5) + hash) + c;

                return hash;
	}

int main(void)
{
	std::string input, input1;

	std::cout << "Enter login: ";
	std::cin >> input;

	std::cout << "Enter password: ";
	std::cin >> input1;

	if (std::atoll(input1.c_str()) == compute(input.c_str()))
		std::cout << "Win\n";
	else
		std::cout << "Lose\n";
}
