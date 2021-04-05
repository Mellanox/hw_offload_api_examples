
DEBUG ?= 0

CC ?= gcc

ifdef RDMA_CORE_PATH
CFLAGS += -I${RDMA_CORE_PATH}/build/include
LDFLAGS += -L${RDMA_CORE_PATH}/build/lib
LDFLAGS += -Wl,-rpath -Wl,${RDMA_CORE_PATH}/build/lib
endif

CFLAGS += -std=c99 -Wall

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
