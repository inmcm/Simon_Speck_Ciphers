all: test user 

GIT_VERSION := $(shell git describe --abbrev=0 --always)

CFLAGS=-c -Wall -Wextra -Wshadow -Wconversion -std=c99 -O3 -DVERSION=\"$(GIT_VERSION)\"

user: simon.o speck.o user_tool.o
	gcc simon.o speck.o user_tool.o -o user

user_tool.o: user_tool.c
	gcc $(CFLAGS) user_tool.c

tests: simon.o speck.o tests.o
	gcc simon.o speck.o tests.o -o tests

tests.o: tests.c
	gcc $(CFLAGS) tests.c

simon.o: simon.c
	gcc $(CFLAGS) simon.c

speck.o: speck.c
	gcc $(CFLAGS) speck.c

test: tests
	./tests

clean:
	rm -rf *o tests user
