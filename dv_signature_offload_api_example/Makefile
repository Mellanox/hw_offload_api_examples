
CC ?= gcc

RDMA_CORE_PATH ?= /labhome/sergeygo/wd/projects/upstream-rdma-core
CFLAGS = -I${RDMA_CORE_PATH}/build/include
LDFLAGS = -L${RDMA_CORE_PATH}/build/lib
LDFLAGS += -Wl,-rpath -Wl,${RDMA_CORE_PATH}/build/lib

LDFLAGS += -libverbs -lmlx5


TARGETS = ibv_sig_example

all: $(TARGETS)

ibv_sig_example: sig_example.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o $(TARGETS)
