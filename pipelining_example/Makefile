
DEBUG ?= 0

CC ?= gcc

RDMA_CORE_PATH ?= /.autodirect/mtrswgwork/allenz/work/new_api/rdma-core

CFLAGS = -I${RDMA_CORE_PATH}/build/include
CFLAGS += -g
CFLAGS += -std=c99 -Wall -Wno-unused-function

LDFLAGS = -L${RDMA_CORE_PATH}/build/lib
LDFLAGS += -Wl,-rpath -Wl,${RDMA_CORE_PATH}/build/lib

LIBS = -lmlx5 -libverbs

ifneq ($(DEBUG),0)
	CFLAGS += -g -DDEBUG
endif

TARGETS = ibv_pipelining_example

all: $(TARGETS)

ibv_pipelining_example: pipelining_example.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o $(TARGETS)
