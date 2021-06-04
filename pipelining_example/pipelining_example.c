#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_WC_PER_POLL 32

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif



static int log_lvl = 1;

#define dbg(format, arg...)						\
	do {								\
		if (log_lvl >= 2) {					\
			int tmp = errno;				\
			fprintf(stdout, "DEBUG: " format, ##arg);	\
			errno = tmp;					\
		}							\
	} while (0)

#define info(format, arg...)						\
	do {								\
		if (log_lvl >= 1) {					\
			int tmp = errno;				\
			fprintf(stdout, "INFO: " format, ##arg);	\
			errno = tmp;					\
		}							\
	} while (0)

#define err(format, arg...)						\
	do {								\
		if (log_lvl >= 0) {					\
			int tmp = errno;				\
			fprintf(stderr, "ERROR: " format, ##arg);	\
			errno = tmp;					\
		}							\
	} while (0)

void set_sig_domain_t10dif_type3(struct mlx5dv_sig_block_domain *, void *);

/* structure of test parameters */
struct config {
	const char *dev_name;   /* IB device name */
	char *server_name;      /* server host name */
	uint32_t tcp_port;      /* server TCP port */
	int ib_port;		/* local IB port to work with */
	int gid_idx;		/* gid index to use */
	int nb;
	int queue_depth;
	int time;		/* test time in seconds */
	long int iters;		/* number of iteratios */
} conf = {
	.dev_name 	= NULL,
	.server_name 	= NULL,
	.tcp_port 	= 19875,
	.ib_port 	= 1,
	.gid_idx 	= 0,
	.nb		= 8,
	.queue_depth 	= 8,
	.time 		= 10,
	.iters		= -1,
};

#define PI_SIZE 8

#define MAX_SEND_WRS 5
#define CQ_SIZE ((MAX_SEND_WRS + 2) * conf.queue_depth)

#define RDMA_SGL_SIZE 4

#define IOV_MAX_SIZE 1

#define SERVER_DATA_SIZE 512

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t {
	uint16_t lid;
	uint8_t gid[16];
	uint32_t qp_num;
} __attribute__((packed));

enum msg_types {
	MSG_TYPE_READ_REQ = 0,
	MSG_TYPE_READ_REP,
	MSG_TYPE_STOP_REQ,
};

struct iov {
	uint64_t addr;
	uint32_t length;
	uint32_t rkey;
} __attribute__((packed));

struct msg_req_hdr {
	uint16_t type;
	uint64_t id;
	uint16_t iov_size;
} __attribute__((packed));

struct msg_req {
	struct msg_req_hdr hdr;
	struct iov iov[IOV_MAX_SIZE];
} __attribute__((packed));

enum msg_rep_status {
	MSG_REP_STATUS_OK = 0,
	MSG_REP_STATUS_SIG_ERROR,
};

struct msg_rep_hdr {
	uint16_t type;
	uint64_t id;
	uint16_t status;
} __attribute__((packed));

struct msg_rep {
	struct msg_rep_hdr hdr;
} __attribute__((packed));

#define MSG_REQ_MAX_SIZE (sizeof(struct msg_req))

#define MSG_REP_MAX_SIZE (sizeof(struct msg_rep))

enum task_status {
	TASK_STATUS_FREE = 0,
	TASK_STATUS_INITED,
	TASK_STATUS_REPLY_SENT,
	TASK_STATUS_WR_CANCELED_WITH_SIG_ERR,
};

struct task {
	uint64_t req_id;
	enum task_status status;
	unsigned iov_size;
	struct iov iov[IOV_MAX_SIZE];
	uint8_t *data;
	uint32_t data_rkey;
	uint32_t data_lkey;
};

struct rx_desc {
	uint8_t *msg;
	struct ibv_sge sge;
	struct ibv_recv_wr wr;
};

struct tx_desc {
	struct mlx5dv_mkey *sig_mr;
};

/* structure of system resources */
struct resources {
	struct ibv_device_attr device_attr;
	/* Device attributes */
	struct ibv_port_attr port_attr;
	/* values to connect to remote side */
	struct cm_con_data_t remote_props;
	struct ibv_context *ib_ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	/* TCP socket file descriptor */
	int sock;

	uint8_t *recv_buf;
	struct ibv_mr *recv_mr;

	uint8_t *data_buf;
	size_t data_buf_size;
	struct ibv_mr *data_mr;

	int num_rx_descs;
	struct rx_desc *rx;
	int num_tx_descs;
	struct tx_desc *tx;
	int num_tasks;
	struct task *tasks;

	uint64_t io_counter;
	unsigned last_data_tail;
	uint64_t polls_counter;
	uint64_t comps_counter;
	uint64_t busy_time;
	uint64_t test_time;
};

static inline int is_server() { return conf.server_name == NULL; }

static inline bool is_client()
{
	return (conf.server_name != NULL);
}

static volatile bool stop = false;

void signal_handler(int sig)
{
	stop = true;
}

int set_signal_handler()
{
	struct sigaction act;
	int rc;
	sigset_t set;

	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;
	rc = sigemptyset(&set);
	if (rc) {
		perror("sigemptyset");
		goto out;
	}

	rc = sigaddset(&set, SIGHUP);
	if (rc) {
		perror("sigaddset");
		goto out;
	}
	rc = sigaddset(&set, SIGINT);
	if (rc) {
		perror("sigaddset");
		goto out;
	}
	rc = sigaddset(&set, SIGALRM);
	if (rc) {
		perror("sigaddset");
		goto out;
	}

	act.sa_mask = set;
	rc = sigaction(SIGHUP, &act, 0);
	if (rc) {
		perror("sigaction");
		goto out;
	}
	rc = sigaction(SIGINT, &act, 0);
	if (rc) {
		perror("sigaction");
		goto out;
	}
	rc = sigaction(SIGALRM, &act, 0);
	if (rc) {
		perror("sigaction");
		goto out;
	}

out:
	return rc;
}

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
	int enable_reuseaddr = 1;
	int tmp;

	struct addrinfo hints = { .ai_flags = AI_PASSIVE,
				  .ai_family = AF_INET,
				  .ai_socktype = SOCK_STREAM };
	if (sprintf(service, "%d", port) < 0)
		goto sock_connect_exit;
	/* Resolve DNS address, use sockfd as temp storage */
	sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);
	if (sockfd) {
		err("%s for %s:%d\n", gai_strerror(sockfd), servername, port);
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
					err("failed connect \n");
					close(sockfd);
					sockfd = -1;
				}
			} else {
				/* Server mode. Set up listening socket an
				 * accept a connection */
				listenfd = sockfd;
				sockfd = -1;

				setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
					   &enable_reuseaddr,
					   sizeof(enable_reuseaddr));

				if (bind(listenfd, iterator->ai_addr,
					 iterator->ai_addrlen))
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
			err("Couldn't connect to %s:%d\n", servername, port);
		else {
			err("accept() failed\n");
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
	if (rc != xfer_size)
		err("Failed writing data during sock_sync_data\n");
	else
		rc = 0;
	while (!rc && total_read_bytes < xfer_size) {
		read_bytes =
		    read(sock, remote_data, xfer_size - total_read_bytes);
		if (read_bytes > 0) {
			total_read_bytes += read_bytes;
			remote_data += read_bytes;
		} else {
			rc = read_bytes;
		}
	}

	return rc;
}

/******************************************************************************
End of socket operations
******************************************************************************/

static inline struct tx_desc *get_tx_desc(struct resources *res,
					  uint32_t req_id) 
{
	return &res->tx[req_id];
}

static inline struct rx_desc *get_rx_desc(struct resources *res,
					  uint32_t req_id)
{
	return &res->rx[req_id];
}

static inline struct task *get_task(struct resources *res, uint32_t req_id)
{
	return &res->tasks[req_id];
}

static inline struct ibv_qp *get_qp(struct resources *res)
{
	return res->qp;
}

static int post_recv(struct ibv_qp *qp, struct rx_desc *desc)
{
	struct ibv_recv_wr *bad_wr;
	int rc;

	rc = ibv_post_recv(qp, &desc->wr, &bad_wr);
	if (rc)
		err("failed to post RR, err %d\n", rc);

	return rc;
}

static int post_recv_all(struct resources *res)
{
	uint64_t req_id;
	struct rx_desc *desc;
	int rc;

	for (req_id = 0; req_id < conf.queue_depth; req_id++) {
		desc = get_rx_desc(res, req_id);

		desc->wr.wr_id = req_id;
		rc = post_recv(get_qp(res), desc);
		if (rc)
			break;
	}

	return rc;
}

static void dereg_mr(struct ibv_mr *mr)
{
	if (mr) {
		ibv_dereg_mr(mr);
	}
}

struct ibv_mr * alloc_mr(struct ibv_pd *pd, size_t size)
{
	int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
		       IBV_ACCESS_REMOTE_WRITE;
	void *ptr;
	struct ibv_mr *mr;

	ptr = calloc(1, size);
	if (!ptr) {
		err("calloc: err %d\n", errno);
		return NULL;
	}

	mr = ibv_reg_mr(pd, ptr, size, mr_flags);
	if (!mr) {
		err("ibv_reg_mr, err %d\n", errno);
		free(ptr);
		return NULL;
	}

	return mr;
}

void free_mr(struct ibv_mr *mr)
{
	void *ptr;

	if (mr) {
		ptr = mr->addr;
		dereg_mr(mr);
		free(ptr);
	}
}

void fill_data_buffer(uint8_t *data, size_t size)
{
	int i, block_num;

	block_num = size / (SERVER_DATA_SIZE + PI_SIZE);
	dbg("size %zu block_num %d pi_size %d\n", size, block_num, PI_SIZE);

	memset(data, 0xA5, size);

	/* corrupt the first byte of data to trigger a signature error */
	*data = ~(*data);

	for (i = 0; i < block_num; i++) {
		data += SERVER_DATA_SIZE;
		/*
		 * Since data and signature properties are currently hardcoded
		 * we pre-calculate T10DIF signature value. It is equal to
		 * 0xec7d5678f0debc9a which splits into CRC 0xec7d, APP_TAG
		 * 0x5678, REF_TAG 0xf0debc9a.
		 */
		*(uint64_t *)data = htonll(0xec7d5678f0debc9a);
		data += PI_SIZE;
	}
}

static struct mlx5dv_mkey *create_sig_mr(struct resources *res)
{
	struct mlx5dv_mkey_init_attr mkey_attr = {};
	mkey_attr.pd = res->pd;
	mkey_attr.max_entries = 1;
	mkey_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
				 MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE;
	struct mlx5dv_mkey *mr;
	mr = mlx5dv_create_mkey(&mkey_attr);
	if (!mr)
		err("ibv_exp_create_mr, err %d", errno);

	return mr;
}

static int create_rx(struct resources *res)
{
	size_t max_msg_size;
	int num_rx_descs = conf.queue_depth;
	size_t offset = 0;
	struct rx_desc *rx;
	int rc, i;

	max_msg_size = is_client() ? MSG_REP_MAX_SIZE : MSG_REQ_MAX_SIZE;

	res->recv_mr = alloc_mr(res->pd, max_msg_size * num_rx_descs);
	if (!res->recv_mr)
		return -ENOMEM;

	res->recv_buf = res->recv_mr->addr;

	rx = calloc(num_rx_descs, sizeof(struct rx_desc));
	if (!rx) {
		rc = -ENOMEM;
		goto err_free_buf;
	}

	for (i = 0; i < num_rx_descs; i++, offset += max_msg_size) {
		struct rx_desc *desc = &rx[i];
		struct ibv_sge *sge = &desc->sge;
		struct ibv_recv_wr *wr = &desc->wr;

		desc->msg = res->recv_buf + offset;

		sge->addr = (uintptr_t)(desc->msg);
		sge->length = max_msg_size;
		sge->lkey = res->recv_mr->lkey;

		wr->sg_list = sge;
		wr->num_sge = 1;
		wr->next = NULL;
		dbg("RX[%d]: addr 0x%lx, length %u, lkey 0x%x\n",
		    i, sge->addr, sge->length, sge->lkey);
	}
	res->rx = rx;
	res->num_rx_descs = num_rx_descs;

	return 0;
err_free_buf:
	free_mr(res->recv_mr);
	res->recv_mr = NULL;
	res->recv_buf = NULL;
	res->rx = NULL;

	return rc;
}

static void destroy_rx(struct resources *res)
{
	if (res->rx) {
		free(res->rx);
		res->rx = NULL;
		res->num_rx_descs = 0;
	}

	free_mr(res->recv_mr);
	res->recv_mr = NULL;
	res->recv_buf = NULL;
}

static int create_tx(struct resources *res)
{
	size_t max_msg_size;
	/* +1 for stop request */
	int num_tx_descs = (conf.queue_depth + 1);
	struct tx_desc *tx;
	size_t offset = 0;
	int rc, i;

	max_msg_size = is_client() ? MSG_REQ_MAX_SIZE : MSG_REP_MAX_SIZE;

	tx = calloc(num_tx_descs, sizeof(struct tx_desc));
	if (!tx) {
		rc = -ENOMEM;
		goto err_exit;
	}

	for (i = 0; i < num_tx_descs; i++, offset += max_msg_size) {
		struct tx_desc *desc = &tx[i];

		desc->sig_mr = create_sig_mr(res);
		if (!desc->sig_mr) {
			rc = errno;
			goto err_free_tx;
		}
	}

	res->tx = tx;
	res->num_tx_descs = num_tx_descs;

	return 0;
err_free_tx:
	for (i--; i >= 0; i--) {
		struct tx_desc *desc = &tx[i];

		if (desc->sig_mr)
			mlx5dv_destroy_mkey(desc->sig_mr);
	}
	free(tx);
err_exit:
	res->tx = NULL;
	return rc;
}

static void destroy_tx(struct resources *res)
{
	int i;

	if (res->tx) {
		for (i = 0; i < res->num_tx_descs; i++) {
			struct tx_desc *desc = &res->tx[i];

			if (desc->sig_mr)
				mlx5dv_destroy_mkey(desc->sig_mr);
		}
		free(res->tx);
		res->tx = NULL;
		res->num_tx_descs = 0;
	}
}

static int create_tasks(struct resources *res)
{
	struct task *tasks;
	size_t task_data_size;
	int num_tasks = conf.queue_depth;
	size_t offset = 0;
	int i, qe, rc;

	if (is_client())
		task_data_size = conf.nb * SERVER_DATA_SIZE;
	else
		task_data_size = conf.nb * (SERVER_DATA_SIZE + PI_SIZE);

	res->data_mr = alloc_mr(res->pd, task_data_size * num_tasks);
	if (!res->data_mr)
		return -ENOMEM;

	res->data_buf = res->data_mr->addr;
	res->data_buf_size = task_data_size * num_tasks;

	tasks = calloc(num_tasks, sizeof(struct task));
	if (!tasks) {
		rc = -ENOMEM;
		goto err_free_buf;
	}

	for (i = 0; i < num_tasks; i++, offset += task_data_size) {
		struct task *task = &tasks[i];

		task->data_rkey = res->data_mr->rkey;
		task->data_lkey = res->data_mr->lkey;
		task->data = res->data_buf + offset;
	}

	res->tasks = tasks;
	res->num_tasks = num_tasks;

	for (qe = 0; qe < conf.queue_depth; qe++) {
		struct task *task = get_task(res, qe);
		task->req_id = qe;

		dbg("TASK[%lu]: data %p, lkey 0x%x, rkey 0x%x\n",
		    task->req_id, task->data, task->data_lkey, task->data_rkey);
	}
	return 0;
err_free_buf:
	free_mr(res->data_mr);
	res->data_buf = NULL;
	res->data_mr = NULL;
	res->data_buf_size = 0;
	return rc;
}

static void destroy_tasks(struct resources *res)
{
	if (res->tasks) {
		free(res->tasks);
		res->tasks = NULL;
		res->num_tasks = 0;
	}
	free_mr(res->data_mr);
	res->data_buf = NULL;
	res->data_mr = NULL;
	res->data_buf_size = 0;
}

static void destroy_qp(struct ibv_qp *qp)
{
	if (qp && ibv_destroy_qp(qp))
		err("failed to destroy QP 0x%x\n", qp->qp_num);
}

static struct ibv_qp *create_qp(struct resources *res)
{
	struct mlx5dv_qp_init_attr mlx5_qp_attr = {};
	struct ibv_qp_init_attr_ex qp_init_attr = {
		.qp_type = IBV_QPT_RC,
		.send_cq = res->cq,
		.recv_cq = res->cq,
		.cap = {
			// more send wr is required because the wr is still
			// in the queue even though the wr is canceled due
			// to signature error
			.max_send_wr = MAX_SEND_WRS * conf.queue_depth,
			.max_recv_wr = 2 * conf.queue_depth,
			.max_send_sge = RDMA_SGL_SIZE,
			.max_recv_sge = 1,
			.max_inline_data = 512,
		},
		.pd = res->pd,
		.comp_mask =
		    IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
		.send_ops_flags =
		    IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_SEND |
		    IBV_QP_EX_WITH_RDMA_READ | IBV_QP_EX_WITH_LOCAL_INV,
	};

	/* signature specific attributes */
	mlx5_qp_attr.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS;
	mlx5_qp_attr.send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE;
	if (is_server()) {
		mlx5_qp_attr.comp_mask |=
		    MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
		mlx5_qp_attr.create_flags = MLX5DV_QP_CREATE_SIG_PIPELINING;
	}
	return mlx5dv_create_qp(res->ib_ctx, &qp_init_attr, &mlx5_qp_attr);
}

int check_sig_mr(struct task *task, struct mlx5dv_mkey *mkey)
{
	struct mlx5dv_mkey_err err_info;
	const char *sig_err = "";
	int rc;

	rc = mlx5dv_mkey_check(mkey, &err_info);
	if (rc) {
		err("check mr status failed\n");
		return rc;
	}

	rc = err_info.err_type;
	switch (rc) {
	case MLX5DV_MKEY_NO_ERR:
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_REFTAG:
		sig_err = "REF_TAG";
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_APPTAG:
		sig_err = "APP_TAG";
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD:
		sig_err = "BLOCK_GUARD";
		break;
	default:
		err("Unknown error has been detected\n");
		return -1;
	}

	if (rc)
		info("REQ[%lu]: SIG ERROR: %s: expected %lu, actual %lu, offset %lu\n",
		     task->req_id, sig_err, err_info.err.sig.expected_value,
		     err_info.err.sig.actual_value, err_info.err.sig.offset);

	return rc;
}

void set_sig_domain_t10dif_type3(struct mlx5dv_sig_block_domain *domain, void *sig)
{
	struct mlx5dv_sig_t10dif *dif = sig;

	memset(dif, 0, sizeof(*dif));
	dif->bg_type = MLX5DV_SIG_T10DIF_CRC;
	dif->bg = 0xffff;
	dif->app_tag = 0x5678;
	dif->ref_tag = 0xf0debc9a;
	dif->flags = MLX5DV_SIG_T10DIF_FLAG_APP_REF_ESCAPE;

	memset(domain, 0, sizeof(*domain));
	domain->sig.dif = dif;
	domain->sig_type = MLX5DV_SIG_TYPE_T10DIF;
	domain->block_size = MLX5DV_BLOCK_SIZE_512;
}

/* helper function to print the content of the async event */
static void print_async_event(struct ibv_context *ctx,
			      struct ibv_async_event *event)
{
	switch (event->event_type) {
	case IBV_EVENT_SQ_DRAINED:
		info("IBV_EVENT_SQ_DRAINED, QP 0x%x\n",
		     event->element.qp->qp_num);
		break;
	default:
		err("Unknown event (%d)\n", event->event_type);
	}
}

void configure_sig_mkey(struct resources *res,
			struct mlx5dv_sig_block_attr *sig_attr,
			struct task *task) {
	struct ibv_qp *qp;
	struct ibv_qp_ex *qpx;
	struct mlx5dv_qp_ex *dv_qp;
	struct mlx5dv_mkey *mkey;
	struct tx_desc *desc;
	struct mlx5dv_mkey_conf_attr conf_attr = {};
	struct ibv_sge sge;
	uint32_t access_flags = IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE;

	desc = get_tx_desc(res, task->req_id);

	mkey = desc->sig_mr;

	qp = get_qp(res);
	qpx = ibv_qp_to_qp_ex(qp);
	dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);

	mlx5dv_wr_mkey_configure(dv_qp, mkey, 3, &conf_attr);
	mlx5dv_wr_set_mkey_access_flags(dv_qp, access_flags);

	sge.addr = (uintptr_t)task->data;
	sge.length = conf.nb * (SERVER_DATA_SIZE + PI_SIZE);
	sge.lkey = task->data_lkey;

	mlx5dv_wr_set_mkey_layout_list(dv_qp, 1, &sge);

	mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);
}

static void reg_data_mrs(struct resources *res, struct task *task)
{
	union {
		struct mlx5dv_sig_t10dif t10dif;
		struct mlx5dv_sig_crc crc;
	} mem_sig;
	struct mlx5dv_sig_block_domain mem;
	struct mlx5dv_sig_block_attr sig_attr = {
		.mem = &mem,
		.wire = NULL,
		.check_mask = MLX5DV_SIG_MASK_T10DIF_GUARD |
			      MLX5DV_SIG_MASK_T10DIF_APPTAG |
			      MLX5DV_SIG_MASK_T10DIF_REFTAG,
	};

	set_sig_domain_t10dif_type3(&mem, &mem_sig);

	configure_sig_mkey(res, &sig_attr, task);
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
	destroy_qp(res->qp);
	destroy_tasks(res);
	destroy_tx(res);
	destroy_rx(res);
	if (res->cq) {
		if (ibv_destroy_cq(res->cq)) {
			err("failed to destroy CQ\n");
			rc = 1;
		}
		res->cq = NULL;
	}
	if (res->pd) {
		if (ibv_dealloc_pd(res->pd)) {
			err("failed to deallocate PD\n");
			rc = 1;
		}
		res->pd = NULL;
	}
	if (res->ib_ctx) {
		if (ibv_close_device(res->ib_ctx)) {
			err("failed to close device context\n");
			rc = 1;
		}
		res->ib_ctx = NULL;
	}

	if (res->sock >= 0) {
		if (close(res->sock)) {
			err("failed to close socket\n");
			rc = 1;
		}
		res->sock = -1;
	}
	return rc;
}

int set_nonblock_async_event_fd(struct ibv_context *ctx)
{
	int flags;
	int rc;

	flags = fcntl(ctx->async_fd, F_GETFL);
	rc = fcntl(ctx->async_fd, F_SETFL, flags | O_NONBLOCK);

	if (rc)
		err("failed to change file descriptor of async event queue\n");

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
	struct mlx5dv_context_attr dv_attr = {};
	struct ibv_device_attr dev_attr;
	int i;
	int num_devices;
	int rc = 0;

	memset(res, 0, sizeof *res);

	if (is_client()) {
		res->sock = sock_connect(conf.server_name, conf.tcp_port);
		if (res->sock < 0) {
			err("failed to establish TCP connection to "
			    "server %s, port %d\n",
			    conf.server_name, conf.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	} else {
		info("waiting on port %d for TCP connection\n",
			conf.tcp_port);
		res->sock = sock_connect(NULL, conf.tcp_port);
		if (res->sock < 0) {
			err("failed to establish TCP connection "
			    "with client on port %d\n",
			    conf.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	}

	/* TCP connection was established, searching for IB devices in host */
	dev_list = ibv_get_device_list(&num_devices);
	if (!dev_list) {
		err("failed to get IB devices list\n");
		rc = 1;
		goto resources_create_exit;
	}
	/* if there isn't any IB device in host */
	if (!num_devices) {
		err("found no RDMA devices\n");
		rc = 1;
		goto resources_create_exit;
	}
	dbg("found %d device(s)\n", num_devices);
	/* search for the specific device we want to work with */
	for (i = 0; i < num_devices; i++) {
		if (!conf.dev_name) {
			conf.dev_name =
			    strdup(ibv_get_device_name(dev_list[i]));
			info("device not specified, using first one found: %s\n",
			     conf.dev_name);
		}
		if (!strcmp(ibv_get_device_name(dev_list[i]), conf.dev_name)) {
			ib_dev = dev_list[i];
			break;
		}
	}
	/* if the device wasn't found in host */
	if (!ib_dev) {
		err("IB device %s wasn't found\n", conf.dev_name);
		rc = 1;
		goto resources_create_exit;
	}
	/* get device handle */
	if (!mlx5dv_is_supported(ib_dev)) {
		err("device %s does not support mlx5dv\n", conf.dev_name);
		rc = 1;
		goto resources_create_exit;
	}
	dv_attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;
	res->ib_ctx = mlx5dv_open_device(ib_dev, &dv_attr);
	if (!res->ib_ctx) {
		err("failed to open device %s errno %d\n",
			conf.dev_name, errno);
		rc = 1;
		goto resources_create_exit;
	}
	/* We are now done with device list, free it */
	ibv_free_device_list(dev_list);
	dev_list = NULL;
	ib_dev = NULL;

	if (set_nonblock_async_event_fd(res->ib_ctx)) {
		rc = 1;
		goto resources_create_exit;
	}

	/* get device capabilities */
	if (ibv_query_device(res->ib_ctx, &dev_attr)) {
		err("ibv_exp_query_device on device %s failed\n",
			ibv_get_device_name(res->ib_ctx->device));
		rc = 1;
		goto resources_create_exit;
	}

	/* query port properties */
	if (ibv_query_port(res->ib_ctx, conf.ib_port, &res->port_attr)) {
		err("ibv_query_port on port %u failed\n", conf.ib_port);
		rc = 1;
		goto resources_create_exit;
	}
	/* allocate Protection Domain */
	res->pd = ibv_alloc_pd(res->ib_ctx);
	if (!res->pd) {
		err("ibv_alloc_pd: err %d\n", errno);
		rc = 1;
		goto resources_create_exit;
	}

	/* number of send WRs + one recv WR */
	res->cq = ibv_create_cq(res->ib_ctx, CQ_SIZE, NULL, NULL, 0);
	if (!res->cq) {
		err("failed to create CQ with %u entries\n", CQ_SIZE);
		rc = 1;
		goto resources_create_exit;
	}

	rc = create_tx(res);
	if (rc) {
		err("create_tx, err %d\n", rc);
		goto resources_create_exit;
	}
	rc = create_rx(res);
	if (rc) {
		err("create_rx, err %d\n", rc);
		goto resources_create_exit;
	}
	rc = create_tasks(res);
	if (rc) {
		err("create_tasks, err %d\n", rc);
		goto resources_create_exit;
	}

	if (is_server())
		fill_data_buffer(res->data_buf, res->data_buf_size);

	res->qp = create_qp(res);
	if (!res->qp) {
		err("failed to create QP\n");
		rc = errno;
		goto resources_create_exit;
	}
resources_create_exit:
	if (dev_list)
		ibv_free_device_list(dev_list);

	if (rc)
		resources_destroy(res);

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
	attr.port_num = conf.ib_port;
	attr.pkey_index = 0;
	attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE;
	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
		IBV_QP_ACCESS_FLAGS;
	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		err("failed to modify QP state to INIT, err %d\n", rc);
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
	attr.path_mtu = IBV_MTU_1024;
	attr.dest_qp_num = remote_qpn;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer = 0x12;
	attr.ah_attr.is_global = 0;
	attr.ah_attr.dlid = dlid;
	attr.ah_attr.sl = 0;
	attr.ah_attr.src_path_bits = 0;
	attr.ah_attr.port_num = conf.ib_port;
	if (conf.gid_idx >= 0) {
		attr.ah_attr.is_global = 1;
		attr.ah_attr.port_num = 1;
		memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
		attr.ah_attr.grh.flow_label = 0;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.sgid_index = conf.gid_idx;
		attr.ah_attr.grh.traffic_class = 0;
	}
	flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
		IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC |
		IBV_QP_MIN_RNR_TIMER;
	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		err("failed to modify QP state to RTR, err %d\n", rc);
	return rc;
}

static int modify_qp_to_err(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_ERR;
	flags = IBV_QP_STATE;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		err("failed to modify QP state to RTR, err %d\n", rc);
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
	int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
		    IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	int rc;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x12;
	attr.retry_cnt = 6;
	attr.rnr_retry = 0;
	attr.sq_psn = 0;
	attr.max_rd_atomic = 1;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		err("failed to modify QP state to RTS, err %d\n", rc);
	return rc;
}

static int modify_qp_from_sqd_to_rts(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	int flags = IBV_QP_STATE | IBV_QP_CUR_STATE;
	int rc;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.cur_qp_state = IBV_QPS_SQD;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		err("failed to modify QP state to RTS, err %d\n", rc);
	return rc;
}

static void flush_qp(struct resources *res) {
	struct timespec sleep = { .tv_sec = 0, .tv_nsec = 1000000, };
	struct ibv_wc wc;

	modify_qp_to_err(res->qp);
	/*
	 * Async events are out of scope of this example.
	 * However, you should use IBV_EVENT_QP_LAST_WQE_REACHED event
	 * instead of a sleep.
	 */
	nanosleep(&sleep, NULL);

	while (ibv_poll_cq(res->cq, 1, &wc)) {
	}
}

/******************************************************************************
 * Function: connect_qp
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
 * Connect the QP. Transition the server side to RTR, sender side to RTS
 ******************************************************************************/
static int connect_qp(struct resources *res)
{
	struct cm_con_data_t local_con_data;
	struct cm_con_data_t remote_con_data;
	struct cm_con_data_t tmp_con_data;
	int rc = 0;
	char temp_char;
	union ibv_gid my_gid;

	if (conf.gid_idx >= 0) {
		rc = ibv_query_gid(res->ib_ctx, conf.ib_port, conf.gid_idx,
				   &my_gid);
		if (rc) {
			err("could not get gid for port %d, index %d\n",
			    conf.ib_port, conf.gid_idx);
			return rc;
		}
	} else
		memset(&my_gid, 0, sizeof my_gid);

	local_con_data.qp_num = htonl(res->qp->qp_num);
	local_con_data.lid = htons(res->port_attr.lid);
	memcpy(local_con_data.gid, &my_gid, 16);
	info("\n");
	info("Local LID = 0x%x\n", res->port_attr.lid);

	if (sock_sync_data(res->sock, sizeof(struct cm_con_data_t),
			   (char *)&local_con_data, (char *)&tmp_con_data)) {
		err("failed to exchange connection data between sides\n");
		rc = 1;
		goto connect_qp_exit;
	}
	remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
	remote_con_data.lid = ntohs(tmp_con_data.lid);
	memcpy(remote_con_data.gid, tmp_con_data.gid, 16);
	/* save the remote side attributes, we will need it for the post SR */
	res->remote_props = remote_con_data;
	info("Remote LID = 0x%x\n", remote_con_data.lid);
	info("Local QP = 0x%x\n", res->qp->qp_num);
	info("Remote QP = 0x%x\n", remote_con_data.qp_num);

	if (conf.gid_idx >= 0) {
		uint8_t *p = my_gid.raw;

		info("Local GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
		     "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		     p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
		     p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

		p = remote_con_data.gid;
		info("Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
		     "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		     p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
		     p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
	}
	info("\n");

	/* modify the QP to init */
	rc = modify_qp_to_init(res->qp);
	if (rc) {
		err("change QP 0x%x state to INIT failed\n", res->qp->qp_num);
		goto connect_qp_exit;
	}

	rc = post_recv_all(res);
	if (rc) {
		err("failed to post RR\n");
		goto connect_qp_exit;
	}

	/* modify the QP to RTR */
	rc = modify_qp_to_rtr(res->qp, remote_con_data.qp_num,
			      remote_con_data.lid, remote_con_data.gid);
	if (rc) {
		err("failed to modify QP 0x%x remote QP 0x%x state to RTR\n",
		    res->qp->qp_num, remote_con_data.qp_num);
		goto connect_qp_exit;
	}
	rc = modify_qp_to_rts(res->qp);
	if (rc) {
		err("failed to modify QP 0x%x state to RTS\n", res->qp->qp_num);
		goto connect_qp_exit;
	}
	dbg("QP state was change to RTS\n");

	/* sync to make sure that both sides are in states that they can connect
	 * to prevent packet loose
	 */
	if (sock_sync_data(res->sock, 1, "Q",
			   &temp_char)) /* just send a dummy char back
					   and forth */
	{
		err("sync error after QP are were moved to RTS\n");
		rc = 1;
	}
connect_qp_exit:
	return rc;
}

static int client_send_req(struct resources *res,
			   uint64_t req_id,
			   enum msg_types type)
{
	struct task *task;
	struct msg_req msg;
	int iov_size = 1;
	size_t msg_length;
	struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(get_qp(res));

	switch (type) {
	case MSG_TYPE_READ_REQ:
	case MSG_TYPE_STOP_REQ:
		break;
	default:
		return -EINVAL;
	}

	msg.hdr.type = htons(type);
	msg.hdr.id = htonll(req_id);
	msg.hdr.iov_size = htons(iov_size);

	msg_length = sizeof(msg.hdr);

	if (MSG_TYPE_STOP_REQ != type) {
		task = get_task(res, req_id);

		msg.iov[0].addr = htonll((uintptr_t)task->data);
		msg.iov[0].length = htonl(conf.nb * SERVER_DATA_SIZE);
		msg.iov[0].rkey = htonl(task->data_rkey);

		msg_length += sizeof(struct iov);
	}

	ibv_wr_start(qpx);
	qpx->wr_id = task->req_id;
	qpx->wr_flags = IBV_SEND_SIGNALED;

	ibv_wr_send(qpx);

	ibv_wr_set_inline_data(qpx, &msg, msg_length);

	dbg("REQ[%lu]: SEND: addr 0x%p, length %zu\n",
	    req_id, &msg, msg_length);

	return ibv_wr_complete(qpx);
}

static int client(struct resources *res)
{
	int req, i, rc, test_result;
	uint64_t req_id;
	enum msg_types req_type = MSG_TYPE_READ_REQ;
	struct ibv_wc wc[MAX_WC_PER_POLL];
	struct timespec start_time;
	struct timespec end_time;
	long unsigned iops;
	struct rx_desc *desc;
	uint8_t *msg;
	struct msg_rep_hdr *hdr;
	enum msg_rep_status status;

	for (req = 0; req < conf.queue_depth; req++) {
		rc = client_send_req(res, req, req_type);
		if (rc)
			return rc;
	}

	rc = clock_gettime(CLOCK_MONOTONIC_COARSE, &start_time);
	if (rc) {
		err("clock_gettime: err %d", rc);
		goto err_exit;
	}

	while (!stop && conf.iters != 0) {
		int polled_comps;

		polled_comps = ibv_poll_cq(res->cq, MAX_WC_PER_POLL, wc);
		res->polls_counter++;
		if (!polled_comps)
			continue;
		if (polled_comps < 0) {
			err("ibv_poll_cq: err %d\n", polled_comps);
			rc = polled_comps;
			break;
		}
		res->comps_counter += polled_comps;

		for (i = 0; i < polled_comps && !stop; ++i) {

			if (wc[i].status != IBV_WC_SUCCESS) {
				err("failed wr_id %lu, opcode %d\n", wc[i].wr_id,
				    wc[i].opcode);
				stop = true;
				break;
			}

			switch (wc[i].opcode) {
			case IBV_WC_SEND:
				dbg("REQ[%lu]: complete\n", wc[i].wr_id);
				break;
			case IBV_WC_RECV:
				dbg("WC: opcode RECV, wr_id %lu\n", wc[i].wr_id);
				desc = get_rx_desc(res, wc[i].wr_id);

				res->io_counter++;
                                conf.iters = (conf.iters > 0) ? conf.iters - 1
                                                              : conf.iters;

                                msg = desc->msg;
				hdr = (struct msg_rep_hdr *)msg;
				req_id = ntohll(hdr->id);
				status = ntohs(hdr->status);

				if (status == MSG_REP_STATUS_OK) {
					dbg("REP[%lu]: received, status OK\n", req_id);
				} else if (status == MSG_REP_STATUS_SIG_ERROR) {
					info("REP[%lu]: received with status SIG_ERROR\n", req_id);
				} else {
					err("REP[%lu]: received, status UNKNOWN\n", req_id);
					rc = -1;
					stop = true;
					break;
				}

				rc = post_recv(get_qp(res), desc);
				if (rc) {
					err("post_recv: WC wr_id %lu, err %d\n",
					    wc[i].wr_id, rc);
					stop = true;
					break;
				}

				rc = client_send_req(res, req_id, MSG_TYPE_READ_REQ);
				if (rc) {
					err("client_send_req: wr_id %lu, req_id %lu, err %d\n",
					    wc[i].wr_id, req_id, rc);
					stop = true;
				}
				break;
			default:
				err("unknown WC opcode %d\n", wc[i].opcode);
				stop = true;
			}
		}
	}
	test_result = rc;

	req_id = conf.queue_depth;
	rc = client_send_req(res, req_id, MSG_TYPE_STOP_REQ);
	if (rc) {
		err("client_send_req: err %d\n", rc);
		test_result = rc;
	}
	rc = clock_gettime(CLOCK_MONOTONIC_COARSE, &end_time);
	if (rc) {
		err("clock_gettime: err %d\n", rc);
		test_result = rc;
		goto err_exit;
	}
	iops = (end_time.tv_sec - start_time.tv_sec) * 1000;
	iops += (end_time.tv_nsec - start_time.tv_nsec) / 1000000;
	if (iops)
		iops = (res->io_counter * 1000) / iops;
	info("IOps : %lu\n", iops);

err_exit:
	flush_qp(res);

	return test_result;
}

static struct task *server_init_task(struct resources *res,
				     uint8_t *msg,
				     size_t msg_len)
{
	struct msg_req_hdr *hdr;
	uint16_t req_type;
	uint64_t req_id;
	struct task *task;
	struct iov *iov;
	unsigned iov_size;
	int i;

	if (msg_len < sizeof(*hdr)) {
		err("received message is too short, length %lu\n", msg_len);
		return NULL;
	}

	hdr = (struct msg_req_hdr *)msg;
	msg += sizeof(*hdr);
	msg_len -= sizeof(*hdr);

	req_type = ntohs(hdr->type);

	if (req_type == MSG_TYPE_STOP_REQ) {
		stop = true;
		dbg("received MSG_TYPE_STOP_REQ\n");
		return NULL;
	}

	req_id = ntohll(hdr->id);
	if (req_id > conf.queue_depth) {
		err("invalid request id(%lu) qd %d\n", req_id, conf.queue_depth);
		return NULL;
	}
	task = get_task(res, req_id);
	if (task->status != TASK_STATUS_FREE) {
		err("request id(%lu) is busy\n", req_id);
		return NULL;
	}

	switch (req_type) {
	case MSG_TYPE_READ_REQ:
		break;
	default:
		err("unknown request type(%u)\n", req_type);
		return NULL;
	}

	iov_size = ntohs(hdr->iov_size);
	if (iov_size > IOV_MAX_SIZE) {
		err("invalid iov_size %u\n", iov_size);
		return NULL;
	}
	task->iov_size = iov_size;

	if (msg_len < (sizeof(*iov) * iov_size)) {
		err("invalid message, iov_size\n");
		return NULL;
	}
	iov = (struct iov *)msg;
	msg_len -= sizeof(*iov) * iov_size;

	for (i = 0; i < iov_size; i++) {
		struct iov *src = &iov[i];
		struct iov *dst = &task->iov[i];

		dst->addr = ntohll(src->addr);
		dst->length = ntohl(src->length);
		dst->rkey = ntohl(src->rkey);
	}
	task->status = TASK_STATUS_INITED;

	return task;
}

static void server_send_reply(struct ibv_qp_ex *qpx,
			      struct task *task,
			      enum msg_rep_status status)
{
	struct msg_rep msg = {
		.hdr = {
			.type = htons(MSG_TYPE_READ_REP),
			.id = htonll(task->req_id),
			.status = htons(status),
		},
	};

	ibv_wr_send(qpx);
	ibv_wr_set_inline_data(qpx, &msg, sizeof(msg));
}

static int server_post_send_reply(struct resources *res,
				  struct task *task,
				  enum msg_rep_status status)
{
	struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(get_qp(res));

	ibv_wr_start(qpx);

	qpx->wr_id = task->req_id;
	qpx->wr_flags = IBV_SEND_SIGNALED;

	server_send_reply(qpx, task, status);

	return ibv_wr_complete(qpx);
}


static void server_rdma_write(struct resources *res, struct task *task) {
	struct ibv_qp_ex *qpx;
	struct tx_desc *desc;
	uint32_t rkey;
	uint64_t remote_addr;
	uint32_t lkey;
	uint64_t addr;
	uint32_t length;

	qpx = ibv_qp_to_qp_ex(get_qp(res));
	desc = get_tx_desc(res, task->req_id);

	rkey = task->iov[0].rkey;
	remote_addr = task->iov[0].addr;

	ibv_wr_rdma_write(qpx, rkey, remote_addr);

	lkey = desc->sig_mr->lkey;
	addr = 0; // offset in sig_mr
	// length of the data on wire domain
	length = conf.nb * SERVER_DATA_SIZE;

	ibv_wr_set_sge(qpx, lkey, addr, length);

	dbg("REQ[%lu]: RDMA_WRITE: remote_addr 0x%lx, rkey 0x%x, "
	    "lkey 0x%x, addr 0x%lx, length %u\n",
	    task->req_id, remote_addr, rkey, lkey, addr, length);
}

static inline int server_handle_read_task(struct resources *res,
					  struct task *task)
{
	struct ibv_qp_ex *qpx;

	qpx = ibv_qp_to_qp_ex(get_qp(res));

	ibv_wr_start(qpx);

	qpx->wr_id = task->req_id;
	qpx->wr_flags = IBV_SEND_INLINE;

	reg_data_mrs(res, task);

	qpx->wr_flags = 0;

	server_rdma_write(res, task);

	qpx->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_FENCE;
	server_send_reply(qpx, task, MSG_REP_STATUS_OK);
	task->status = TASK_STATUS_REPLY_SENT;

	dbg("REP[%lu]: send, status OK\n", task->req_id);

	return ibv_wr_complete(qpx);
}

static inline int server_handle_async_event(struct resources *res)
{
	int i, canceled_wrs;
	struct ibv_qp *qp;
	struct task *task;

	struct tx_desc *desc;

	struct ibv_qp_ex *qpx;
	struct mlx5dv_qp_ex *dv_qp;

	qp = res->qp;
	qpx = ibv_qp_to_qp_ex(qp);
	dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);

	for (i = 0; i < conf.queue_depth; i++) {
		task = get_task(res, i);
		if (task->status != TASK_STATUS_REPLY_SENT)
			/* Skip non-active tasks */
			continue;

		desc = get_tx_desc(res, i);
		if (check_sig_mr(task, desc->sig_mr)) {
			/* Cancel SEND WR with reply OK, if signature error was detected */
			canceled_wrs = mlx5dv_qp_cancel_posted_send_wrs(dv_qp, task->req_id);
			if (canceled_wrs < 0) {
				err("mlx5dv_qp_cancel_posted_send_wrs: err %d\n", canceled_wrs);
				return canceled_wrs;
			} else {
				/* Mark the task as canceled */
				info("REQ[%lu]: cancel wrs %d\n", task->req_id, canceled_wrs);
				task->status = TASK_STATUS_WR_CANCELED_WITH_SIG_ERR;
			}
		}
	}

	/* Modify the QP to RTS state, to continue SEND WRs processing */
	return modify_qp_from_sqd_to_rts(qp);
}

static inline int server_handle_request(struct resources *res,
					struct ibv_wc *wc)
{
	struct rx_desc *desc;
	struct task *task;
	uint8_t *msg;
	unsigned msg_len;
	int rc;

	desc = get_rx_desc(res, wc->wr_id);
	msg = desc->msg;
	msg_len = wc->byte_len;

	task = server_init_task(res, msg, msg_len);
	if (!task)
		return stop ? 0 : -1;

	dbg("REQ[%lu]: received\n", task->req_id);
	rc = post_recv(get_qp(res), desc);
	if (rc)
		return -1;

	return server_handle_read_task(res, task);
}

static inline int server_handle_wc(struct resources *res, struct ibv_wc *wc)
{
	int rc = 0;
	struct task *task;

	if (wc->status != IBV_WC_SUCCESS) {
		err("failed WR id %lu, opcode %d\n", wc->wr_id, wc->opcode);
		return -1;
	}

	switch (wc->opcode) {
	case IBV_WC_RDMA_READ:
	case IBV_WC_RDMA_WRITE:
	case IBV_WC_DRIVER1:
		err("unexpected completion for non-signal WR, wr_id %lu, opcode %d\n",
		    wc->wr_id, wc->opcode);
		rc = -1;
		break;
	case IBV_WC_SEND:
		task = get_task(res, wc->wr_id);
		if (task->status != TASK_STATUS_WR_CANCELED_WITH_SIG_ERR) {
			task->status = TASK_STATUS_FREE;
			dbg("REP[%lu]: completed\n", task->req_id);
		} else {
			info("REP[%lu]: canceled reply with status OK\n", task->req_id);
			info("REP[%lu]: send reply with status SIG_ERROR\n", task->req_id);
			task->status = TASK_STATUS_REPLY_SENT;
			rc = server_post_send_reply(res, task, MSG_REP_STATUS_SIG_ERROR);
			if (rc)
				err("server_post_send_reply: err %d\n", rc);
		}
		break;
	case IBV_WC_RECV:
		rc = server_handle_request(res, wc);
		if (rc)
			err("server_handle_request: err %d\n", rc);
		break;
	default:
		err("unknown WC opcode %d\n", wc->opcode);
		rc = -1;
	}

	return rc;
}

static inline int server_check_sqd_event(struct resources *res)
{
	struct ibv_async_event event;
	int rc;

	rc = ibv_get_async_event(res->ib_ctx, &event);
	if (rc)
		return (errno == EAGAIN) ? 0 : -1;

	print_async_event(res->ib_ctx, &event);
	if (IBV_EVENT_SQ_DRAINED == event.event_type) {
		 rc = 1;
	}
	ibv_ack_async_event(&event);

	return rc;
}

static int server(struct resources *res) {
	struct ibv_wc wc[MAX_WC_PER_POLL];
	int polled_comps;
	/* The number of completions we must process before handle SQD event. */
	int pending_comps;
	int i;
	int rc = 0;
	bool first;
	int sq_drained = 0; /* Is there a not-handled SQD event? */
	struct timespec start_ts, end_ts, first_ts;

	while (!stop) {
		if (!sq_drained) {
			/* Check for a new SQD event */
			sq_drained = server_check_sqd_event(res);
			if (sq_drained < 0) {
				err("server_check_sqd_event failed\n");
				rc = sq_drained;
				break;
			}

			if (sq_drained) {
				/*
				 * Got a new SQD event. Need to handle it.
				 *
				 * Firstly, we need to poll and process all
				 * completions produced before the SQD event.
				 * Let's assume the worst case: the CQ is full,
				 * and we must process CQ_SIZE completions.
				 */
				pending_comps = CQ_SIZE;
			}
		}
		polled_comps = ibv_poll_cq(res->cq, MAX_WC_PER_POLL, wc);
		res->polls_counter++;
		if (polled_comps < 0) {
			err("ibv_poll_cq failed\n");
			rc = polled_comps;
			break;
		}

		if (polled_comps == 0) {
			if (!sq_drained)
				continue;
			/*
			 * The CQ is empty. We can handle the SQD
			 * event immediately.
			 */
			pending_comps = 0;
		}

		if (sq_drained) {
			if (polled_comps == MAX_WC_PER_POLL)
				pending_comps -= polled_comps;
			else
				/*
				 * (polled_comps < MAX_WC_PER_POLL)
				 * All pendind completions were polled.
				 * We can handle the SQD after processing
				 * the polled completions.
				 */
				pending_comps = 0;
		}

		res->comps_counter += polled_comps;
		clock_gettime(CLOCK_MONOTONIC, &start_ts);
		if (!first) {
			first_ts = start_ts;
			first = true;
		}

		/* Handle all polled completions */
		for (i = 0; i < polled_comps; ++i) {
			rc = server_handle_wc(res, &wc[i]);
			if (rc) {
				err("server_handle_wc, err %d\n", rc);
				stop = true;
				break;
			}
		}

		if (sq_drained && pending_comps <= 0) {
			rc = server_handle_async_event(res);
			if (rc) {
				err("server_handle_async_event, err %d\n", rc);
				stop = true;
				break;
			}
			sq_drained = false;
		}

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		res->busy_time +=
		    (end_ts.tv_sec - start_ts.tv_sec) * 1000000000 +
		    (end_ts.tv_nsec - start_ts.tv_nsec);
	}

	clock_gettime(CLOCK_MONOTONIC, &end_ts);
	res->test_time += (end_ts.tv_sec - first_ts.tv_sec) * 1000000000 +
			  (end_ts.tv_nsec - first_ts.tv_nsec);

	flush_qp(res);

	return rc;
}

static void print_config(void) {
	info(" ------------------------------------------------\n");
	info(" Device name : \"%s\"\n", conf.dev_name);
	info(" IB port : %u\n", conf.ib_port);
	if (conf.server_name)
		info(" IP : %s\n", conf.server_name);

	info(" TCP port : %u\n", conf.tcp_port);
	if (conf.gid_idx >= 0)
		info(" GID index : %u\n", conf.gid_idx);

	info(" Block size : %u\n", SERVER_DATA_SIZE);
	info(" I/O size : %d\n", conf.nb * SERVER_DATA_SIZE);
	info(" Queue depth : %d\n", conf.queue_depth);
	info(" ------------------------------------------------\n\n");
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

static void usage(const char *argv0) {
	info("Usage:\n");
	info(" %s start a server and wait for connection\n", argv0);
	info(" %s <host> connect to server at <host>\n", argv0);
	info("\n");
	info("Options:\n");
	info(" -h, --help                   print this message\n");
	info(" -p, --port <port>            listen on/connect to port <port> (default 18515)\n");
	info(" -d, --ib-dev <dev>           use IB device <dev> (default first device found)\n");
	info(" -i, --ib-port <port>         use port <port> of IB device (default 1)\n");
	info(" -g, --gid-idx <gid index>    gid index to be used in GRH (default not used)\n");
	info(" -n, --number-of-blocks <NB>  Number of blocks per RDMA operation (default 8)\n");
	info(" -q, --queue-depth <num>      number of simultaneous requests per QP that "
					   "a client can send to the server.\n");
	info(" -t, --time <num>             stop after <num> seconds (default 10)\n");
	info(" -c, --iters <num>            stop after <num> iterations (default unlimited)\n");
	info(" -l, --log-level <lvl>        0 - ERROR, 1 - INFO, 2 - DEBUG\n");
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

	/* parse the command line parameters */
	while (1) {
		int c;
		static struct option long_options[] = {
			{ .name = "help",		.has_arg = 1, .val = 'h' },
			{ .name = "port",		.has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",		.has_arg = 1, .val = 'd' },
			{ .name = "ib-port",		.has_arg = 1, .val = 'i' },
			{ .name = "gid-idx",		.has_arg = 1, .val = 'g' },
			{ .name = "number-of-blocks",	.has_arg = 1, .val = 'n' },
			{ .name = "queue-depth",	.has_arg = 1, .val = 'q' },
			{ .name = "time",		.has_arg = 1, .val = 't' },
			{ .name = "iters",		.has_arg = 1, .val = 'c' },
			{ .name = "log-level",		.has_arg = 1, .val = 'l' },
			{ .name = NULL,			.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "hp:d:i:g:n:q:t:c:l:", long_options,
				NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'p':
			conf.tcp_port = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			conf.dev_name = strdup(optarg);
			break;
		case 'i':
			conf.ib_port = strtoul(optarg, NULL, 0);
			if (conf.ib_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'g':
			conf.gid_idx = strtoul(optarg, NULL, 0);
			if (conf.gid_idx < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'n':
			conf.nb = strtoul(optarg, NULL, 0);
			if (conf.nb < 1) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'q':
			conf.queue_depth = strtoul(optarg, NULL, 0);
			if (conf.queue_depth < 1) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 't':
			conf.time = strtoul(optarg, NULL, 0);
			if (conf.time < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'c':
			conf.iters = strtoul(optarg, NULL, 0);
			if (conf.iters < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'l':
			log_lvl = strtoul(optarg, NULL, 0);
			if (log_lvl < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* parse the last parameter (if exists) as the server name */
	if (optind == argc - 1)
		conf.server_name = argv[optind];
	else if (optind < argc) {
		usage(argv[0]);
		return 1;
	}

	print_config();

	rc = resources_create(&res);
	if (rc) {
		err("failed to create resources: %s\n", strerror(rc));
		if (rc == EOPNOTSUPP || rc == ENOTSUP)
			rc = 0;
		goto main_exit;
	}

	if (connect_qp(&res)) {
		err("failed to connect QP\n");
		goto main_exit;
	}
	if (set_signal_handler()) {
		goto main_exit;
	}

	if (is_client()) {
		alarm(conf.time);
		rc = client(&res);
	} else {
		/*
		 * We observe lower test results if the server stops before
		 * the client. Add + 1 to avoid that.
		 */
		alarm(conf.time + 1);
		rc = server(&res);
	}

	// avoid crash while calculate time/comp bellow
	if (!res.comps_counter) {
		res.comps_counter = 1;
	}

	info("\n");
	info("Polls %lu, completions %lu, comps/poll %.1f\n",
	     res.polls_counter, res.comps_counter,
	     (double)res.comps_counter / res.polls_counter);
	if (!is_client()) {
		info("Busy time %lu ns, test time %lu ns, busy "
		      "percent %.2f, time/comp %lu ns\n",
			res.busy_time, res.test_time,
			(double)res.busy_time /
			    ((uint64_t)conf.time * 1000000000) * 100,
			res.busy_time / res.comps_counter);
	}
main_exit:
	if (resources_destroy(&res)) {
		err("failed to destroy resources\n");
		rc = 1;
	}
	if (conf.dev_name)
		free((char *)conf.dev_name);

	info("\n");
	info("test result is %d\n", rc);

	return rc;
}
