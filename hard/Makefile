CFLAGS := -g3 -O3 -Wall

all: main post
	./post main.o
	clang++ -static main1.o -o lab
	strip --strip-all lab
	upx --best --lzma -o bin lab
        
main: main.cpp
	clang++ -I./plusaes/include $(CFLAGS) $< -c

post: post.cpp
	clang++ -I./ELFIO -I./plusaes/include $(CFLAGS) $< -o post
