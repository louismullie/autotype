CC ?= cc
CFLAGS ?= -std=c11 -O3 -Wall -Wextra -Iinclude
LDFLAGS ?=

SRCS = src/type.c src/solver.c src/main.c
OBJS = $(SRCS:.c=.o)
BIN = stc_solve

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c include/stc.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

test: $(BIN)
	./$(BIN)
