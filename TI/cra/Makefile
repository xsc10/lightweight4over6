all : cra

cra:cra.h main.c packet.c table.c
	gcc cra.h packet.c socket.c table.c print.c main.c -g -o cra
#cra: main.o socket.o packet.o table.o
#	gcc main.o socket.o packet.o table.o -o cra
#socket.o:socket.c cra.h
#	gcc socket.c -c -g -o socket.o
#packet.o:packet.c cra.h
#	gcc packet.c -c -g -o packet.o
#table.o:table.c cra.h
#	gcc table.c -c -g -o table.o
#main.o:main.c cra.h
#	gcc main.c -c -g -o main.o

clean :
	rm -f cra
	rm -f *.o
