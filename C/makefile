all: tests

CFLAGS=-c -Wall -Wextra -Wshadow -Wconversion -std=c99 -O3

tests: simon.o speck.o tests.o
	gcc simon.o speck.o tests.o -o tests

tests.o: tests.c
	gcc $(CFLAGS) tests.c

simon.o: Simon.c
	gcc $(CFLAGS) Simon.c

speck.o: Speck.c
	gcc $(CFLAGS) Speck.c

clean:
	rm -rf *o tests