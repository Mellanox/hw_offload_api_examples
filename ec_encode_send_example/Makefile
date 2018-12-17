CC ?= gcc

JERASURE_INSTALL_DIR ?=
JERASURE_INC ?= $(JERASURE_INSTALL_DIR)/include
JERASURE_LIB ?= $(JERASURE_INSTALL_DIR)/lib

CFLAGS += -g
CPPFLAGS += -I$(JERASURE_INC) -I$(JERASURE_INC)/jerasure
LDFLAGS += -L$(JERASURE_LIB) -libverbs -lgf_complete -lJerasure

TARGETS = ec_encode_send_example

all: $(TARGETS)

ec_encode_send_example: ec_encode_send_example.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o $(TARGETS)
