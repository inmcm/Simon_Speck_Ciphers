all: tests

tests: simon.o speck.o tests.o
	gcc simon.o speck.o tests.o -o tests

tests.o: tests.c
	gcc -c tests.c

simon.o: Simon.c
	gcc -c Simon.c

speck.o: Speck.c
	gcc -c Speck.c

clean:
	rm -rf *o tests