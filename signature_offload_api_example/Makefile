
CC ?= gcc

LDFLAGS += -libverbs


TARGETS = ibv_sig_example

all: $(TARGETS)

ibv_sig_example: sig_example.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o $(TARGETS)
