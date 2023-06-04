CC=g++
CPPCC=g++
FLAGS=-I ../include -fPIC

MAIN_DEPEN=mutator.o depen map.cpp map.h cmp-functions.o
MAIN_ARGS= -std=c++11 ./xxhash/xxhash.o -shared mutator.o cmp-functions.o map.cpp -o mutator.so

TEST_FILE=test1.c

default: angora
default: FLAGS += -O3

angora: $(MAIN_DEPEN)
	$(CC) $(FLAGS) $(MAIN_ARGS) 

print: FLAGS += -DDEBUG

debug: FLAGS += -DDEBUG
debug: FLAGS += -O0
debug: FLAGS += -g
debug: angora

cmp-functions.o: cmp-functions.c
	gcc $(FLAGS) -c cmp-functions.c -o cmp-functions.o

mutator.o: mutator.c 
	gcc $(FLAGS) -c mutator.c -o mutator.o 

depen:
	make -C xxhash all

test: angora
	afl-cc $(TEST_FILE) -o test
	AFL_LLVM_CMPLOG=1 afl-cc $(TEST_FILE) -o testcmp
	mkdir -p input
	echo abcd > input/0

test-without: test
	afl-fuzz -i input -o output -c ./testcmp -m none -- ./test

test-run: test
	AFL_CUSTOM_MUTATOR_LIBRARY="./mutator.so" afl-fuzz -i input -o output -c ./testcmp -m none -- ./test

test-debug: test
	AFL_DEBUG_CHILD=1 AFL_CUSTOM_MUTATOR_ONLY=1 AFL_CUSTOM_MUTATOR_LIBRARY="./mutator.so" gdb --args afl-fuzz -i input -o output -c ./testcmp -m none -- ./test

clean:
	$(RM) *.o
	$(RM) *.so testcmp test
	$(RM) -rf input output
