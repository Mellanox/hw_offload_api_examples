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
	u_int32_t tcp_port;	/* server TCP port */
	int ib_port;		/* local IB port to work with */
	int gid_idx;		/* gid index to use */
	char *input_file_name;
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

struct config_t config = {
	.dev_name	= NULL,
	.server_name	= NULL,
	.tcp_port	= 19875,
	.ib_port	= 1,
	.gid_idx	= -1,
	.input_file_name = NULL,
	.block_size	= 512,
	.k		= 3,
	.m		= 2,
	.w		= 8,
	.max_inflight_calcs = MAX_INFLIGHT_CALCS
};

/******************************************************************************
Socket operations
For simplicity, the example program uses TCP sockets to exchange control
information. If a TCP/IP stack/connection is not available, connection manager
(CM) may be used to pass this information. Use of CM is beyond the scope of
this example
******************************************************************************/

/******************************************************************************
 * Function: sock_connect
 *
 * Input
 * servername URL of server to connect to (NULL for server mode)
 * port port of service
 *
 * Output
 * none
 *
 * Returns
 * socket (fd) on success, negative error code on failure
 *
 * Description
 * Connect a socket. If servername is specified a client connection will be
 * initiated to the indicated server and port. Otherwise listen on the
 * indicated port for an incoming connection.
 *
 ******************************************************************************/
static int sock_connect(const char *servername, int port)
{
	struct addrinfo *resolved_addr = NULL;
	struct addrinfo *iterator;
	char service[6];
	int sockfd = -1;
	int listenfd = 0;
	int tmp;

	struct addrinfo hints = { .ai_flags = AI_PASSIVE,
				  .ai_family = AF_INET,
				  .ai_socktype = SOCK_STREAM };
	if (sprintf(service, "%d", port) < 0)
		goto sock_connect_exit;
	/* Resolve DNS address, use sockfd as temp storage */
	sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);
	if (sockfd) {
		fprintf(stderr, "%s for %s:%d\n", gai_strerror(sockfd),
			servername, port);
		goto sock_connect_exit;
	}
	/* Search through results and find the one we want */
	for (iterator = resolved_addr; iterator; iterator = iterator->ai_next) {
		sockfd = socket(iterator->ai_family, iterator->ai_socktype,
				iterator->ai_protocol);
		if (sockfd >= 0) {
			if (servername) {
				/* Client mode. Initiate connection to remote */
				if ((tmp = connect(sockfd, iterator->ai_addr,
						   iterator->ai_addrlen))) {
					fprintf(stdout, "failed connect \n");
					close(sockfd);
					sockfd = -1;
				}
			} else {
				/* Server mode. Set up listening socket an accept a connection */
				listenfd = sockfd;
				sockfd = -1;
				if (bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))
					goto sock_connect_exit;

				listen(listenfd, 1);
				sockfd = accept(listenfd, NULL, 0);
			}
		}
	}

sock_connect_exit:
	if (listenfd)
		close(listenfd);
	if (resolved_addr)
		freeaddrinfo(resolved_addr);
	if (sockfd < 0) {
		if (servername)
			fprintf(stderr, "Couldn't connect to %s:%d\n",
				servername, port);
		else {
			perror("server accept");
			fprintf(stderr, "accept() failed\n");
		}
	}
	return sockfd;
}

/******************************************************************************
 * Function: sock_sync_data
 *
 * Input
 * sock socket to transfer data on
 * xfer_size size of data to transfer
 * local_data pointer to data to be sent to remote
 *
 * Output
 * remote_data pointer to buffer to receive remote data
 *
 * Returns
 * 0 on success, negative error code on failure
 *
 * Description
 * Sync data across a socket. The indicated local data will be sent to the
 * remote. It will then wait for the remote to send its data back. It is
 * assumed that the two sides are in sync and call this function in the proper
 * order. Chaos will ensue if they are not. :)
 *
 * Also note this is a blocking function and will wait for the full data to be
 * received from the remote.
 *
 ******************************************************************************/
int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{
	int rc;
	int read_bytes = 0;
	int total_read_bytes = 0;
	rc = write(sock, local_data, xfer_size);
	if (rc < xfer_size)
		fprintf(stderr, "Failed writing data during sock_sync_data\n");
	else
		rc = 0;
	while (!rc && total_read_bytes < xfer_size) {
		read_bytes = read(sock, remote_data, xfer_size);
		if (read_bytes > 0)
			total_read_bytes += read_bytes;
		else
			rc = read_bytes;
	}
	return rc;
}
/******************************************************************************
End of socket operations
******************************************************************************/

/* poll_completion */
/******************************************************************************
 * Function: poll_completion
 *
 * Input
 * res pointer to resources structure
 *
 * Output
 * wc completion
 *
 * Returns
 * 0 on success, 1 on failure
 *
 * Description
 * Poll the completion queue for a single event. This function will continue to
 * poll the queue until MAX_POLL_CQ_TIMEOUT milliseconds have passed.
 *
 ******************************************************************************/
static int
poll_completion(struct resources *res, struct ibv_wc *wc)
{
	unsigned long start_time_msec;
	unsigned long cur_time_msec;
	struct timeval cur_time;
	int poll_result;
	int rc = 0;
	/* poll the completion for a while before giving up of doing it .. */
	gettimeofday(&cur_time, NULL);
	start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	do {
		poll_result = ibv_poll_cq(res->cq, 1, wc);
		gettimeofday(&cur_time, NULL);
		cur_time_msec =
			(cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	} while ((poll_result == 0) &&
		 ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));
	if (poll_result < 0) {
		/* poll CQ failed */
		fprintf(stderr, "poll CQ failed\n");
		rc = 1;
	} else if (poll_result == 0) {
		/* the CQ is empty */
		fprintf(stderr,
			"completion wasn't found in the CQ after timeout\n");
		rc = 1;
	} else {
		/* CQE found */
		/* fprintf(stdout, "completion was found in CQ with status 0x%x, opcode %u, qp_num 0x%x\n",
		   wc->status, wc->opcode, wc->qp_num); */
		/* check the completion status (here we don't care about the completion
		 * opcode */
		if (wc->status != IBV_WC_SUCCESS) {
			fprintf(stderr,
				"got bad completion with status: %s (0x%x), vendor syndrome: 0x%x\n",
				ibv_wc_status_str(wc->status),
				wc->status, wc->vendor_err);
			rc = 1;
		}
	}
	return rc;
}

static struct ibv_qp *
create_qp(struct resources *res)
{
	struct ibv_qp* qp;
	struct ibv_exp_qp_init_attr qp_init_attr;
	/* create the Queue Pair */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 0;
	qp_init_attr.send_cq = res->cq;
	qp_init_attr.recv_cq = res->cq;
	qp_init_attr.cap.max_send_wr = config.max_inflight_calcs * 2;
	qp_init_attr.cap.max_recv_wr = 1;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	/* Extended attributes */
	qp_init_attr.pd = res->pd;
	qp_init_attr.exp_create_flags = IBV_EXP_QP_CREATE_EC_PARITY_EN;
	/* @todo: check which flags is correct: EC_PARITY_EN or CROSS_CHANNEL */
	/* IBV_EXP_QP_CREATE_CROSS_CHANNEL; */
	qp_init_attr.comp_mask = IBV_EXP_QP_INIT_ATTR_PD | IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS;
	qp = ibv_exp_create_qp(res->ib_ctx, &qp_init_attr);
	if (!qp) {
		fprintf(stderr, "failed to create QP\n");
		return NULL;
	}

	fprintf(stdout, "QP was created, QP number=0x%x\n", qp->qp_num);
	return qp;
}

static void free_encode_matrix(uint8_t *en_mat)
{
	free(en_mat);
}

static int alloc_encode_matrix(int k, int m, int w, uint8_t **en_mat, int **encode_matrix)
{
	uint8_t *matrix;
	int *rs_mat;
	int i, j;

	matrix = calloc(1, m * k);
	if (!matrix) {
		fprintf(stderr, "Failed to allocate encode matrix\n");
		return -ENOMEM;
	}

	rs_mat = reed_sol_vandermonde_coding_matrix(k, m, w);
	if (!rs_mat) {
		fprintf(stderr, "Failed to allocate reed sol matrix\n");
		return -EINVAL;
	}

	for (i = 0; i < m; i++)
		for (j = 0; j < k; j++)
			matrix[j*m+i] = (uint8_t)rs_mat[i*k+j];

	*en_mat = matrix;
	*encode_matrix = rs_mat;

	return 0;
}

static void destroy_ec_blocks(struct resources *res)
{
	int i;
	for (i = 0; i < config.max_inflight_calcs; ++i) {
		struct ec_block *ecb = &res->ec_blocks[i];
		if (ecb->mr) {
			ibv_dereg_mr(ecb->mr);
		}
		if (ecb->buf) {
			free(ecb->buf);
		}
	}
}

static int
allocate_ec_blocks(struct resources *res)
{
	int i, j;
	int rc = 0;

	for (i = 0; i < config.max_inflight_calcs; ++i) {
		struct ec_block *ecb = &res->ec_blocks[i];

		/* Allocated and register buffer for data and code */
		ecb->buf = calloc(1, config.block_size * (config.k + config.m));
		if (!ecb->buf) {
			fprintf(stderr, "Failed to allocate EC block buffer\n");
			rc = 1;
			goto allocate_ec_blocks_exit;
		}
		ecb->mr = ibv_reg_mr(res->pd, ecb->buf,
				     config.block_size * (config.k + config.m),
				     IBV_ACCESS_LOCAL_WRITE);
		if (!ecb->mr) {
			fprintf(stderr, "Failed to register EC block MR\n");
			rc = 1;
			goto allocate_ec_blocks_exit;
		}

		ecb->ec_mem.data_blocks = ecb->sges;
		ecb->ec_mem.num_data_sge = config.k;
		ecb->ec_mem.code_blocks = ecb->sges + config.k;
		ecb->ec_mem.num_code_sge = config.m;
		ecb->ec_mem.block_size = config.block_size;

		/* Initialize data and code stripes */
		for (j = 0; j < config.k + config.m; ++j) {
			struct ibv_exp_ec_stripe *stripe = (j < config.k) ?
				&ecb->data_stripes[j] : &ecb->code_stripes[j - config.k];
			struct ibv_sge *sge = &ecb->sges[j];
			struct ibv_send_wr *swr = &ecb->send_wrs[j];
			struct ibv_recv_wr *rwr = &ecb->recv_wrs[j];

			stripe->qp = res->qps[j];
			stripe->wr = swr;

			sge->addr = (uintptr_t)(ecb->buf + config.block_size * j);
			sge->length = config.block_size;
			sge->lkey = ecb->mr->lkey;

			swr->wr_id = (uintptr_t)ecb;
			swr->sg_list = sge;
			swr->num_sge = 1;
			swr->opcode = IBV_WR_SEND;
			swr->send_flags = IBV_SEND_SIGNALED;
			swr->next = NULL;

			rwr->wr_id = (uintptr_t)ecb;
			rwr->sg_list = sge;
			rwr->num_sge = 1;
			rwr->next = NULL;
		}
	}
 allocate_ec_blocks_exit:
	if (rc) {
		destroy_ec_blocks(res);
	}
	return rc;
}

static void
destroy_ec_calc(struct resources *res)
{
	if (res->ec_calc) {
		ibv_exp_dealloc_ec_calc(res->ec_calc);
	}
	/* @todo: check if jearsure_encode_mat shall be released */
	if (res->ec_encode_mat) {
		free_encode_matrix(res->ec_encode_mat);
	}
}

static int
create_ec_calc(struct resources *res)
{
	struct ibv_exp_ec_calc_init_attr init_attr = {};
	int rc = 0;

	rc = alloc_encode_matrix(config.k, config.m, config.w,
				 &res->ec_encode_mat, &res->jerasure_encode_mat);
	if (rc) {
		fprintf(stderr, "Failed to allocate encode matrix\n");
		goto create_ec_calc_exit;
	}
	init_attr.max_inflight_calcs = config.max_inflight_calcs;
	init_attr.k = config.k;
	init_attr.m = config.m;
	init_attr.w = config.w;
	init_attr.max_data_sge = config.k; /* @todo: check if 1 is not enough */
	init_attr.max_code_sge = config.m;
	init_attr.encode_matrix = res->ec_encode_mat;
	/* @todo: check why polling is required to encode and send */
	init_attr.polling = 0;
	init_attr.comp_mask = IBV_EXP_EC_CALC_ATTR_MAX_INFLIGHT | IBV_EXP_EC_CALC_ATTR_K |
		IBV_EXP_EC_CALC_ATTR_M | IBV_EXP_EC_CALC_ATTR_W | IBV_EXP_EC_CALC_ATTR_MAX_DATA_SGE |
		IBV_EXP_EC_CALC_ATTR_MAX_CODE_SGE | IBV_EXP_EC_CALC_ATTR_ENCODE_MAT |
		IBV_EXP_EC_CALC_ATTR_POLLING;
	res->ec_calc = ibv_exp_alloc_ec_calc(res->pd, &init_attr);
	if (!res->ec_calc) {
		fprintf(stderr, "Failed to allocate ec_calc structure\n");
		rc = 1;
		goto create_ec_calc_exit;
	}

	fprintf(stdout, "Created EC calc resources\n");
 create_ec_calc_exit:
	if (rc) {
		destroy_ec_calc(res);
	}
	return rc;
}

/******************************************************************************
 * Function: resources_create
 *
 * Input
 * res pointer to resources structure to be filled in
 *
 * Output
 * res filled in with resources
 *
 * Returns
 * 0 on success, 1 on failure
 *
 * Description
 *
 * This function creates and allocates all necessary system resources. These
 * are stored in res.
 *****************************************************************************/

static int resources_create(struct resources *res)
{
	struct ibv_device **dev_list = NULL;
	struct ibv_device *ib_dev = NULL;

	size_t size;
	int i;
	int cq_size = 0;
	int num_devices;
	int rc = 0;

	memset(res, 0, sizeof *res);
	res->sock = -1;

	/* if client side */
	if (config.server_name) {
		res->sock = sock_connect(config.server_name, config.tcp_port);
		if (res->sock < 0) {
			fprintf(stderr,
				"failed to establish TCP connection to server %s, port %d\n",
				config.server_name, config.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	} else {
		fprintf(stdout, "waiting on port %d for TCP connection\n",
			config.tcp_port);
		res->sock = sock_connect(NULL, config.tcp_port);
		if (res->sock < 0) {
			fprintf(stderr,
				"failed to establish TCP connection with client on port %d\n",
				config.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	}

	fprintf(stdout, "TCP connection was established\n");
	fprintf(stdout, "searching for IB devices in host\n");
	/* get device names in the system */
	dev_list = ibv_get_device_list(&num_devices);
	if (!dev_list) {
		fprintf(stderr, "failed to get IB devices list\n");
		rc = 1;
		goto resources_create_exit;
	}
	/* if there isn't any IB device in host */
	if (!num_devices) {
		fprintf(stderr, "found %d device(s)\n", num_devices);
		rc = 1;
		goto resources_create_exit;
	}
	fprintf(stdout, "found %d device(s)\n", num_devices);
	/* search for the specific device we want to work with */
	for (i = 0; i < num_devices; i++) {
		if (!config.dev_name) {
			config.dev_name =
				strdup(ibv_get_device_name(dev_list[i]));
			fprintf(stdout,
				"device not specified, using first one found: %s\n",
				config.dev_name);
		}
		if (!strcmp(ibv_get_device_name(dev_list[i]),
			    config.dev_name)) {
			ib_dev = dev_list[i];
			break;
		}
	}
	/* if the device wasn't found in host */
	if (!ib_dev) {
		fprintf(stderr, "IB device %s wasn't found\n", config.dev_name);
		rc = 1;
		goto resources_create_exit;
	}
	/* get device handle */
	res->ib_ctx = ibv_open_device(ib_dev);
	if (!res->ib_ctx) {
		fprintf(stderr, "failed to open device %s\n", config.dev_name);
		rc = 1;
		goto resources_create_exit;
	}
	/* We are now done with device list, free it */
	ibv_free_device_list(dev_list);
	dev_list = NULL;
	ib_dev = NULL;

	/* query port properties */
	if (ibv_query_port(res->ib_ctx, config.ib_port, &res->port_attr)) {
		fprintf(stderr, "ibv_query_port on port %u failed\n",
			config.ib_port);
		rc = 1;
		goto resources_create_exit;
	}
	/* allocate Protection Domain */
	res->pd = ibv_alloc_pd(res->ib_ctx);
	if (!res->pd) {
		fprintf(stderr, "ibv_alloc_pd failed\n");
		rc = 1;
		goto resources_create_exit;
	}

	cq_size = 16;
	res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
	if (!res->cq) {
		fprintf(stderr, "failed to create CQ with %u entries\n",
			cq_size);
		rc = 1;
		goto resources_create_exit;
	}

	/* Create QPs */
	for (i = 0; i < config.k + config.m; ++i) {
		res->qps[i] = create_qp(res);
		if (!res->qps[i]) {
			rc = 1;
			goto resources_create_exit;
		}
	}

	if (config.server_name) {
		rc = create_ec_calc(res);
		if (rc) {
			goto resources_create_exit;
		}
	}

	rc = allocate_ec_blocks(res);
	if (rc) {
		fprintf(stderr, "Failed to allocate EC blocks\n");
		goto resources_create_exit;
	}


resources_create_exit:
	if (rc) {
		destroy_ec_blocks(res);
		if (res->ec_calc) {
			destroy_ec_calc(res);
		}
		/* Error encountered, cleanup */
		for (i = 0; i < config.k + config.m; ++i) {
			if (res->qps[i]) {
				ibv_destroy_qp(res->qps[i]);
				res->qps[i] = NULL;
			}
		}
		if (res->cq) {
			ibv_destroy_cq(res->cq);
			res->cq = NULL;
		}
		if (res->pd) {
			ibv_dealloc_pd(res->pd);
			res->pd = NULL;
		}
		if (res->ib_ctx) {
			ibv_close_device(res->ib_ctx);
			res->ib_ctx = NULL;
		}

		if (dev_list) {
			ibv_free_device_list(dev_list);
			dev_list = NULL;
		}

		if (res->sock >= 0) {
			if (close(res->sock))
				fprintf(stderr, "failed to close socket\n");
			res->sock = -1;
		}
	}
	return rc;
}
/******************************************************************************
 * Function: modify_qp_to_init
 *
 * Input
 * qp QP to transition
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, ibv_modify_qp failure code on failure
 *
 * Description
 * Transition a QP from the RESET to INIT state
 ******************************************************************************/
static int modify_qp_to_init(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = config.ib_port;
	attr.pkey_index = 0;
	attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE;
	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
		IBV_QP_ACCESS_FLAGS;
	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to INIT\n");
	return rc;
}

/******************************************************************************
 * Function: modify_qp_to_rtr
 *
 * Input
 * qp QP to transition
 * remote_qpn remote QP number
 * dlid destination LID
 * dgid destination GID (mandatory for RoCEE)
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, ibv_modify_qp failure code on failure
 *
 * Description
 * Transition a QP from the INIT to RTR state, using the specified QP number
 ******************************************************************************/
static int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn,
			    uint16_t dlid, uint8_t *dgid)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_256;
	attr.dest_qp_num = remote_qpn;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer = 0x12;
	attr.ah_attr.is_global = 0;
	attr.ah_attr.dlid = dlid;
	attr.ah_attr.sl = 0;
	attr.ah_attr.src_path_bits = 0;
	attr.ah_attr.port_num = config.ib_port;
	if (config.gid_idx >= 0) {
		attr.ah_attr.is_global = 1;
		attr.ah_attr.port_num = 1;
		memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
		attr.ah_attr.grh.flow_label = 0;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.sgid_index = config.gid_idx;
		attr.ah_attr.grh.traffic_class = 0;
	}
	flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
		IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC |
		IBV_QP_MIN_RNR_TIMER;
	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTR: err %d\n", rc);
	return rc;
}

/******************************************************************************
 * Function: modify_qp_to_rts
 *
 * Input
 * qp QP to transition
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, ibv_modify_qp failure code on failure
 *
 * Description
 * Transition a QP from the RTR to RTS state
 ******************************************************************************/
static int modify_qp_to_rts(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x12;
	attr.retry_cnt = 6;
	attr.rnr_retry = 7;
	attr.sq_psn = 0;
	attr.max_rd_atomic = 1;
	flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
		IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTS\n");
	return rc;
}
/******************************************************************************
 * Function: connect_qps
 *
 * Input
 * res pointer to resources structure
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, error code on failure
 *
 * Description
 * Connect QPs and transition them to RTS
 ******************************************************************************/
static int connect_qps(struct resources *res)
{
	struct cm_con_data_t local_con_data[config.k + config.m];
	struct cm_con_data_t remote_con_data[config.k + config.m];
	int rc = 0;
	char temp_char;
	union ibv_gid my_gid;
	int i;

	if (config.gid_idx >= 0) {
		rc = ibv_query_gid(res->ib_ctx, config.ib_port, config.gid_idx,
				   &my_gid);
		if (rc) {
			fprintf(stderr,
				"could not get gid for port %d, index %d\n",
				config.ib_port, config.gid_idx);
			return rc;
		}
	} else {
		memset(&my_gid, 0, sizeof my_gid);
	}
	for (i = 0; i < config.k + config.m; ++i) {
		local_con_data[i].qp_num = htonl(res->qps[i]->qp_num);
		local_con_data[i].lid = htons(res->port_attr.lid);
		memcpy(local_con_data[i].gid, &my_gid, 16);
	}
	fprintf(stdout, "\nLocal LID = 0x%x\n", res->port_attr.lid);

	if (sock_sync_data(res->sock, sizeof(local_con_data),
			   (char *)&local_con_data,
			   (char *)&remote_con_data) < 0) {
		fprintf(stderr,
			"failed to exchange connection data between sides\n");
		rc = 1;
		goto connect_qp_exit;
	}
	for (i = 0; i < config.k + config.m; ++i) {
		remote_con_data[i].qp_num = ntohl(remote_con_data[i].qp_num);
		remote_con_data[i].lid = ntohs(remote_con_data[i].lid);
	}
	if (config.gid_idx >= 0) {
		uint8_t *p = remote_con_data[0].gid;
		fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],p[10], p[11], p[12], p[13], p[14], p[15]);
	}

	for (i = 0; i < config.k + config.m; ++i) {
		struct ibv_qp *qp = res->qps[i];
		fprintf(stdout, "Local QP number = 0x%x\n", qp->qp_num);
		fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data[i].qp_num);
		fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data[i].lid);
		/* modify the QP to init */
		rc = modify_qp_to_init(qp);
		if (rc) {
			fprintf(stderr, "change QP state to INIT failed\n");
			goto connect_qp_exit;
		}

		/* modify the QP to RTR */
		rc = modify_qp_to_rtr(qp, remote_con_data[i].qp_num,
				      remote_con_data[i].lid, remote_con_data[i].gid);
		if (rc) {
			fprintf(stderr, "failed to modify QP state to RTR\n");
			goto connect_qp_exit;
		}
		rc = modify_qp_to_rts(qp);
		if (rc) {
			fprintf(stderr, "failed to modify QP state to RTS\n");
			goto connect_qp_exit;
		}
		fprintf(stdout, "QP state was change to RTS\n");
	}
	/* sync to make sure that both sides are in states that they can connect to
	 * prevent packet loose */
	if (sock_sync_data(
		    res->sock, 1, "Q",
		    &temp_char)) /* just send a dummy char back and forth */
	{
		fprintf(stderr, "sync error after QPs are were moved to RTS\n");
		rc = 1;
	}
connect_qp_exit:
	return rc;
}

/******************************************************************************
 * Function: resources_destroy
 *
 * Input
 * res pointer to resources structure
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, 1 on failure
 *
 * Description
 * Cleanup and deallocate all resources used
 ******************************************************************************/
static int resources_destroy(struct resources *res)
{
	int rc = 0;
	int i;

	destroy_ec_blocks(res);
	if (res->ec_calc) {
		destroy_ec_calc(res);
	}
	for (i = 0; i < config.k + config.m; ++i) {
		if (res->qps[i])
			if (ibv_destroy_qp(res->qps[i])) {
				fprintf(stderr, "failed to destroy QP\n");
				rc = 1;
			}
	}
	if (res->cq)
		if (ibv_destroy_cq(res->cq)) {
			fprintf(stderr, "failed to destroy CQ\n");
			rc = 1;
		}
	if (res->pd)
		if (ibv_dealloc_pd(res->pd)) {
			fprintf(stderr, "failed to deallocate PD\n");
			rc = 1;
		}
	if (res->ib_ctx)
		if (ibv_close_device(res->ib_ctx)) {
			fprintf(stderr, "failed to close device context\n");
			rc = 1;
		}

	if (res->sock >= 0)
		if (close(res->sock)) {
			fprintf(stderr, "failed to close socket\n");
			rc = 1;
		}
	return rc;
}

static int
post_receive_block(struct resources *res, struct ec_block *ec_block)
{
	struct ibv_recv_wr *bad_wr;
	int i;
	int rc = 0;

	for (i = 0; i < config.k + config.m; ++i) {
		rc = ibv_post_recv(res->qps[i], &ec_block->recv_wrs[i], &bad_wr);
		if (rc) {
			fprintf(stderr, "failed to post RR: err %d\n", rc);
			break;
		}
		/* fprintf(stdout, "Receive Request was posted to QP num 0x%x, length %d\n",
			res->qps[i]->qp_num,
			ec_block->recv_wrs[i].sg_list[0].length); */
	}
	return rc;
}

static int
receive_file(struct resources *res, const char *file_suffix)
{
	FILE *fds[config.k + config.m];
	int rc = 0;
	int i;
	uint32_t fsize;
	uint32_t flen = 0;
	uint32_t tmp;

	sock_sync_data(res->sock, sizeof(fsize), (char *)&tmp, (char *)&fsize);
	fsize = ntohl(fsize);

	memset(fds, 0, sizeof(fds));
	for (i = 0; i < config.k + config.m; ++i) {
		char fname[1024];
		snprintf(fname, sizeof(fname), "%s%02d%s",
			 (i < config.k) ? "data" : "code", i, file_suffix);
		fds[i] = fopen(fname, "w");
		if (!fds[i]) {
			rc = 1;
			goto receive_file_exit;
		}
	}

	while (flen < fsize) {
		struct ec_block *ecb = &res->ec_blocks[0];
		post_receive_block(res, ecb);
		for (i = 0; i < config.k + config.m; ++i) {
			struct ibv_wc wc;
			rc = poll_completion(res, &wc);
			if (rc) {
				fprintf(stderr, "Failed to poll for completion %d\n", i);
				goto receive_file_exit;
			}
		}
		for (i = 0; i < config.k + config.m; ++i) {
			size_t len;
			len = fwrite(ecb->buf + i * config.block_size,
				     1, config.block_size, fds[i]);
			if (!len) {
				fprintf(stderr, "Failed to read input file\n");
				rc = 1;
				goto receive_file_exit;
			}
		}
		flen += config.block_size * config.k;
	}

 receive_file_exit:
	for (i = 0; i < config.k + config.m; ++i) {
		if (fds[i]) {
			fclose(fds[i]);
		}
	}
	return rc;
}

int server(struct resources *res)
{
	int rc = 0;

	rc = receive_file(res, "_hw");
	if (rc) {
		goto err_exit;
	}
	rc = receive_file(res, "_sw");
	if (rc) {
		goto err_exit;
	}
err_exit:
	return rc;
}

static int
encode_and_send_block(struct resources *res, struct ec_block *ec_block)
{
	int rc = 0;
	rc = ibv_exp_ec_encode_send(res->ec_calc, &ec_block->ec_mem,
				    ec_block->data_stripes, ec_block->code_stripes);
	if (rc) {
		fprintf(stderr, "Failed to encode and send: err %d\n", rc);
	}

	return rc;
}

static int
encode_and_send_block_sw(struct resources *res, struct ec_block *ec_block)
{
	int rc = 0;
	int i;
	struct ibv_send_wr *bad_wr;
	if (config.w == 8) {
		char *data_ptrs[config.k];
		char *code_ptrs[config.m];
		for (i = 0; i < config.k; ++i) {
			data_ptrs[i] = ec_block->buf + i * config.block_size;
		}
		for (i = 0; i < config.m; ++i) {
			code_ptrs[i] = ec_block->buf + (config.k + i) * config.block_size;
		}
		jerasure_matrix_encode(config.k, config.m, config.w,
				       res->jerasure_encode_mat,
				       data_ptrs, code_ptrs,
				       config.block_size);
		for (i = 0; i < config.k + config.m; ++i) {
			rc = ibv_post_send(res->qps[i], &ec_block->send_wrs[i], &bad_wr);
			if (rc) {
				fprintf(stderr, "Failed to post SR\n");
				break;
			}
		}
	} else {
		fprintf(stderr, "SW encode is not supported for w!= 8\n");
		rc = 1;
	}
	return rc;
}

static int
encode_and_send_file(struct resources *res,
		     int (*encode_fn)(struct resources *, struct ec_block *))
{
	FILE *fd = NULL;
	int rc = 0;
	uint32_t fsize;
	uint32_t tmp;

	fd = fopen(config.input_file_name, "r");
	if (!fd) {
		rc = 1;
		goto encode_and_send_file_exit;
	}

	fseek(fd, 0, SEEK_END);
	fsize = ftell(fd);
	rewind(fd);
	fsize = htonl(fsize);
	sock_sync_data(res->sock, sizeof(fsize), (char *)&fsize, (char *)&tmp);

	while (!feof(fd)) {
		int i;
		struct ibv_wc wc;
		size_t len = config.block_size * config.k;
		struct ec_block *ecb = &res->ec_blocks[0];

		memset(ecb->buf, 0, len);
		len = fread(ecb->buf, 1, len, fd);
		if (!len) {
			fprintf(stderr, "Failed to read input file\n");
			rc = 1;
			goto encode_and_send_file_exit;
		}
		rc = encode_fn(res, ecb);
		if (rc) {
			goto encode_and_send_file_exit;
		}
		for (i = 0; i < config.k + config.m; ++i) {
			rc = poll_completion(res, &wc);
			if (rc) {
				goto encode_and_send_file_exit;
			}
		}
	}

 encode_and_send_file_exit:
	if (fd) {
		fclose(fd);
	}
	return rc;
}


int client(struct resources *res)
{
	int rc = 0;

	rc = encode_and_send_file(res, encode_and_send_block);
	if (rc) {
		goto err_exit;
	}
	rc = encode_and_send_file(res, encode_and_send_block_sw);
	if (rc) {
		goto err_exit;
	}
err_exit:
	return rc;
}


static void print_config(void)
{
	fprintf(stdout, " ------------------------------------------------\n");
	fprintf(stdout, " Device name : \"%s\"\n", config.dev_name);
	fprintf(stdout, " IB port : %u\n", config.ib_port);
	if (config.server_name)
		fprintf(stdout, " IP : %s\n", config.server_name);

	fprintf(stdout, " TCP port : %u\n", config.tcp_port);
	if (config.gid_idx >= 0)
		fprintf(stdout, " GID index : %u\n", config.gid_idx);

	fprintf(stdout, " Input file name : %u\n", config.input_file_name);
	fprintf(stdout, " Block size : %u\n", config.block_size);
	fprintf(stdout, " K : %u\n", config.k);
	fprintf(stdout, " M : %u\n", config.m);
	fprintf(stdout, " Max inflight calcs : %u\n", config.max_inflight_calcs);
	fprintf(stdout,
		" ------------------------------------------------\n\n");
}
/******************************************************************************
 * Function: usage
 *
 * Input
 * argv0 command line arguments
 *
 * Output
 * none
 *
 * Returns
 * none
 *
 * Description
 * print a description of command line syntax
 ******************************************************************************/

static void usage(const char *argv0)
{
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, " %s [options] start a server and wait for connection\n", argv0);
	fprintf(stdout, " %s [options] <host> connect to server at <host>\n", argv0);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout,
		" -p, --port <port>            listen on/connect to port <port> (default 18515)\n");
	fprintf(stdout,
		" -d, --ib-dev <dev>           use IB device <dev> (default first device found)\n");
	fprintf(stdout,
		" -i, --ib-port <port>         use port <port> of IB device (default 1)\n");
	fprintf(stdout,
		" -g, --gid_idx <git index>    gid index to be used in GRH "
		"(default not used)\n");
	fprintf(stdout,
		" -f, --input-file <path>      input file name\n");
	fprintf(stdout,
		" -b, --block-size <size>      size of data block (default 512)\n");
	fprintf(stdout,
		" -k, --data-devices <N>       number of data devices (default 3, max 16)\n");
	fprintf(stdout,
		" -m, --code-devices <N>       number of code devices (default 2, max 4)\n");
}

/******************************************************************************
 * Function: main
 *
 * Input
 * argc number of items in argv
 * argv command line parameters
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, 1 on failure
 *
 * Description
 * Main program code
 ******************************************************************************/
int main(int argc, char *argv[])
{
	struct resources res;
	int rc = 1;
	int i;
	char temp_char;

	/* parse the command line parameters */
	while (1) {
		int c;
		static struct option long_options[] = {
			{ .name = "port",		.has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",		.has_arg = 1, .val = 'd' },
			{ .name = "ib-port",		.has_arg = 1, .val = 'i' },
			{ .name = "gid-idx",		.has_arg = 1, .val = 'g' },
			{ .name = "input-file",	.has_arg = 1, .val = 'f' },
			{ .name = "block-size",	.has_arg = 1, .val = 'b' },
			{ .name = "k",			.has_arg = 1, .val = 'k' },
			{ .name = "m",			.has_arg = 1, .val = 'm' },
			{ .name = "help",		.has_arg = 0, .val = 'h' },
			{ .name = NULL,		.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "p:d:i:g:f:b:k:m:h", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'p':
			config.tcp_port = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			config.dev_name = strdup(optarg);
			break;
		case 'i':
			config.ib_port = strtoul(optarg, NULL, 0);
			if (config.ib_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'g':
			config.gid_idx = strtoul(optarg, NULL, 0);
			if (config.gid_idx < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'f':
			config.input_file_name = strdup(optarg);
			break;
		case 'b':
			config.block_size = strtoul(optarg, NULL, 0);
			break;
		case 'k':
			config.k = strtoul(optarg, NULL, 0);
			if ((config.k < 1) ||(config.k > MAX_K)) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'm':
			config.m = strtoul(optarg, NULL, 0);
			if ((config.m < 1) || (config.m > MAX_M)) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'h':
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* parse the last parameter (if exists) as the server name */
	if (optind == argc - 1)
		config.server_name = argv[optind];
	else if (optind < argc) {
		usage(argv[0]);
		return 1;
	}

	print_config();

	if (resources_create(&res)) {
		fprintf(stderr, "failed to create resources\n");
		goto main_exit;
	}

	if (connect_qps(&res)) {
		fprintf(stderr, "failed to connect QPs\n");

		goto main_exit;
	}

	fprintf(stdout, "Data QPs: ");
	for (i = 0; i < config.k; ++i) {
		fprintf(stdout, "%x, ", res.qps[i]->qp_num);
	}
	fprintf(stdout, "\nCode QPs: ");
	for (i = 0; i < config.m; ++i) {
		fprintf(stdout, "%x, ", res.qps[config.k + i]->qp_num);
	}
	fprintf(stdout, "\n");
	if (config.server_name)
		rc = client(&res);
	else
		rc = server(&res);

main_exit:
	if (resources_destroy(&res)) {
		fprintf(stderr, "failed to destroy resources\n");
		rc = 1;
	}
	if (config.dev_name)
		free((char *)config.dev_name);
	fprintf(stdout, "\ntest result is %d\n", rc);

	return rc;
}
