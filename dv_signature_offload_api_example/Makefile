
CC ?= gcc

ifdef RDMA_CORE_PATH
CFLAGS = -I$(RDMA_CORE_PATH)/build/include
LDFLAGS = -L$(RDMA_CORE_PATH)/build/lib
LDFLAGS += -Wl,-rpath -Wl,$(RDMA_CORE_PATH)/build/lib
endif

LIBS = -lmlx5 -libverbs


TARGETS = ibv_sig_example

all: $(TARGETS)

ibv_sig_example: sig_example.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o $(TARGETS)
