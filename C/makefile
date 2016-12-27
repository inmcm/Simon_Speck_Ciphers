all: tests

tests: simon.o tests.o
	gcc simon.o tests.o -o tests

tests.o: tests.c
	gcc -c tests.c

simon.o: Simon.c
	gcc -c Simon.c

clean:
	rm -rf *o tests