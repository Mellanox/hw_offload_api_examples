# Define a common prefix where binaries and docs install
PREFIX = /usr
sbindir = bin

CC = gcc
CFLAGS += -g -ggdb -Wall -W -D_GNU_SOURCE
LDFLAGS = -Wl,-rpath,/usr/lib -libverbs -lgf_complete -lJerasure -lpthread -lrdmacm

OBJECTS_LAT = ec_encoder_async.o ec_perf_async.o ec_perf_sync.o ec_encoder.o ec_decoder.o ec_updater.o ec_common.o common.o 
TARGETS = ibv_ec_encoder_async ibv_ec_perf_async ibv_ec_perf_sync ibv_ec_encoder ibv_ec_decoder ibv_ec_updater 

all: $(TARGETS)

ibv_ec_encoder: ec_encoder.o ec_common.o common.o
	$(CC) $(CFLAGS) -o $@ ec_encoder.o ec_common.o common.o $(LDFLAGS)

ibv_ec_decoder: ec_decoder.o ec_common.o common.o
	$(CC) $(CFLAGS) -o $@ ec_decoder.o ec_common.o common.o $(LDFLAGS)

ibv_ec_updater: ec_updater.o ec_common.o common.o
	$(CC) $(CFLAGS) -o $@ ec_updater.o ec_common.o common.o $(LDFLAGS)

ibv_ec_perf_sync: ec_perf_sync.o ec_common.o common.o
	$(CC) $(CFLAGS) -o $@ ec_perf_sync.o ec_common.o common.o $(LDFLAGS)

ibv_ec_perf_async: ec_perf_async.o ec_common.o common.o
	$(CC) $(CFLAGS) -o $@ ec_perf_async.o ec_common.o common.o $(LDFLAGS)

ibv_ec_encoder_async: ec_encoder_async.o ec_common.o common.o
	$(CC) $(CFLAGS) -o $@ ec_encoder_async.o ec_common.o common.o $(LDFLAGS)

install:
	install -d -m 755 $(PREFIX)/$(sbindir)
	install -m 755 $(TARGETS) $(PREFIX)/$(sbindir)
clean:
	rm -f $(OBJECTS_LAT) $(TARGETS)
