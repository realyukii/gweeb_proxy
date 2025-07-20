clang -DENABLE_LOG=false -c -fsanitize=address,undefined,leak -fPIE -fno-omit-frame-pointer -g -Og ./gwsocks5lib.c -o ./build/gwsocks5lib.o
clang -DENABLE_LOG=false -c -fsanitize=address,undefined,leak -fPIE -fno-omit-frame-pointer -g -Og ./gwdnslib.c -o ./build/gwdnslib.o
clang -DENABLE_LOG=false -c -fsanitize=address,undefined,leak -fPIE -fno-omit-frame-pointer -g -Og ./linux.c -o ./build/linux.o
clang -DENABLE_LOG=false -c -fsanitize=address,undefined,leak -fPIE -fno-omit-frame-pointer -g -Og ./general.c -o ./build/general.o
clang -DENABLE_LOG=false -c -fsanitize=address,undefined,leak -fPIE -fno-omit-frame-pointer -g -Og ./gwproxy.c -o ./build/gwproxy.o

clang -fsanitize=address,undefined,leak -fPIE -pie -fno-omit-frame-pointer -g -Og build/gwproxy.o build/gwdnslib.o build/gwsocks5lib.o build/linux.o build/general.o -o ./build/gwproxy