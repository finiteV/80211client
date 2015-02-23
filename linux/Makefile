all:main

main : main.o watcher.o
	gcc -o main main.o watcher.o -lpcap
	
main.o : main.c
	gcc -g -c main.c
	
watcher.o : watcher.c data.h
	gcc -g -c watcher.c
	
clean:
	rm -f main *.o
