all: 
	gcc -m32 -no-pie -nostdlib -o sum sum.c
	gcc -m32 -no-pie -nostdlib -o fib fib.c
	gcc -m32 -o loader loader.c
	ar rcs lib_simpleloader.a sum fib loader
	sum fib loader lib_simpleloader.a

clean:
	-@rm -f sum fib loader lib_simpleloader.a
