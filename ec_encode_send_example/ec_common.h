#ifndef EC_COMMON_H
#define EC_COMMON_H

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <jerasure.h>
#include <jerasure/reed_sol.h>



/* poll CQ timeout in millisec (2 seconds) */
#define MAX_POLL_CQ_TIMEOUT 2000

/* structure of test parameters */
struct config_t {
	const char *dev_name;	/* IB device name */
	char *server_name;	/* server host name */
	uint32_t tcp_port;	/* server TCP port */
	int ib_port;		/* local IB port to work with */
	int gid_idx;		/* gid index to use */
	char *input_file_name;
	uint32_t time;
	int block_size;
	int k;
	int m;
	int w;
	int max_inflight_calcs;
};

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t {
	uint32_t qp_num;
	uint16_t lid;
	uint8_t gid[16];
} __attribute__((packed));


#define MAX_K 16
#define MAX_M 4
#define MAX_INFLIGHT_CALCS 1
struct ec_block {
	uint8_t *buf;
	struct ibv_mr *mr;
	struct ibv_exp_ec_mem ec_mem;
	struct ibv_exp_ec_stripe data_stripes[MAX_K];
	struct ibv_exp_ec_stripe code_stripes[MAX_M];
	struct ibv_send_wr send_wrs[MAX_K + MAX_M];
	struct ibv_recv_wr recv_wrs[MAX_K + MAX_M];
	struct ibv_sge sges[MAX_K + MAX_M];
};

/* structure of system resources */
struct resources {
	struct ibv_device_attr device_attr;
	/* Device attributes */
	struct ibv_port_attr port_attr;
	struct ibv_context *ib_ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qps[MAX_K + MAX_M];

	int sock; /* TCP socket file descriptor */

	/* EC offload resources */
	struct ibv_exp_ec_calc *ec_calc;
	uint8_t *ec_encode_mat;
	int *jerasure_encode_mat;
	struct ec_block ec_blocks[MAX_INFLIGHT_CALCS];
};

int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data);
int poll_completion(struct resources *res, struct ibv_wc *wc);
int resources_create(struct resources *res);
int resources_destroy(struct resources *res);
int connect_qps(struct resources *res);
int post_receive_block(struct resources *res, struct ec_block *ec_block);
int encode_and_send_block(struct resources *res, struct ec_block *ec_block);
int encode_and_send_block_sw(struct resources *res, struct ec_block *ec_block);

#endif /* EC_COMMON_H */
