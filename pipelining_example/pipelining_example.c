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

/* poll CQ timeout in millisec (2 seconds) */
#define MAX_POLL_CQ_TIMEOUT 2000
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

enum test_type {
	TEST_TYPE_WRITE,
	TEST_TYPE_READ,
	TEST_TYPE_UNKNOWN,
};

enum signature_types {
	SIG_TYPE_CRC32 = 0,
	SIG_TYPE_MAX,
};

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
	enum test_type type;
	int time; /* test time in seconds */
	enum ibv_mtu mtu;
} conf = {
	.dev_name 	= NULL,
	.server_name 	= NULL,
	.tcp_port 	= 19875,
	.ib_port 	= 1,
	.gid_idx 	= -1,
	.nb		= 8,
	.queue_depth 	= 1,
	.type 		= TEST_TYPE_WRITE,
	.time 		= 10,
	.mtu 		= IBV_MTU_1024,
};

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t {
	uint16_t lid;
	uint8_t gid[16];
	uint32_t qp_num;
} __attribute__((packed));

enum msg_types {
	MSG_TYPE_READ_REQ = 0,
	MSG_TYPE_READ_REP,
	MSG_TYPE_WRITE_REQ,
	MSG_TYPE_WRITE_REP,
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
	uint32_t inline_data_size;
} __attribute__((packed));

enum msg_rep_status {
	MSG_REP_STATUS_OK = 0,
	MSG_REP_STATUS_FAIL,
};

struct msg_rep_hdr {
	uint16_t type;
	uint64_t id;
	uint16_t status;
	uint32_t inline_data_size;
} __attribute__((packed));

#define PI_SIZE 8

#define MAX_SEND_WRS 4
#define CQ_SIZE ((MAX_SEND_WRS + 2) * conf.queue_depth)

#define RDMA_SGL_SIZE 4

#define IOV_MAX_SIZE 1

#define MSG_REQ_HDR_SIZE (sizeof(struct msg_req_hdr))
#define MSG_REQ_MAX_SIZE (MSG_REQ_HDR_SIZE + MSG_MAX_INLINE_DATA_SIZE)

#define MSG_REP_HDR_SIZE (sizeof(struct msg_rep_hdr))
#define MSG_REP_MAX_SIZE (MSG_REP_HDR_SIZE + MSG_MAX_INLINE_DATA_SIZE)
#define MSG_MAX_INLINE_DATA_SIZE 512

/*
 * Data structure in server
 * ###################################################
 * # Data (512)                                  #PI#
 * ###################################################
 * # Data (512)                                  #PI#
 * ###################################################
 * # Data (512)                                  #PI#
 * ###################################################
 */
#define SERVER_DATA_SIZE 512 

struct buffer {
	uint8_t *ptr;
	size_t size;
	size_t mem_size;
	struct ibv_mr *mr;
};

struct ind_buffer {
	struct buffer *orig;
	size_t offset;
	size_t size;
};

enum task_types {
	TASK_TYPE_READ,
	TASK_TYPE_WRITE
};

enum task_status {
	TASK_STATUS_FREE = 0,
	TASK_STATUS_INITED,
	TASK_STATUS_RDMA_READ_DONE,
	TASK_STATUS_RDMA_WRITE_DONE,
	TASK_STATUS_IO_DONE,
	TASK_STATUS_REPLY_SENT,
	TASK_STATUS_WR_CANCELED_WITH_ERR,
};

struct task {
	uint64_t req_id;
	enum task_types type;
	enum task_status status;
	unsigned iov_size;
	struct iov iov[IOV_MAX_SIZE];
	unsigned data_len;
	struct ind_buffer data_buf;
};

struct rx_desc {
	struct ind_buffer recv_buf;
	struct ibv_sge sge;
	struct ibv_recv_wr wr;
};

struct tx_desc {
	struct ind_buffer send_buf;
	struct ibv_sge msg_sge;
	struct ibv_sge sge;
	struct mlx5dv_mkey *sig_mr;
	struct ibv_send_wr wrs[MAX_SEND_WRS];
	unsigned next_wr_idx;
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
	struct buffer send_buf;
	struct buffer recv_buf;
	struct buffer data_buf;

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

static inline int server_check_async_event(struct resources *res);

static inline int is_server() { return conf.server_name == NULL; }

static inline struct ibv_send_wr *first_send_wr(struct tx_desc *desc)
{
	return desc->next_wr_idx ? desc->wrs : NULL;
}

static inline struct ibv_send_wr *next_send_wr(struct tx_desc *desc)
{
	struct ibv_send_wr *wrs = desc->wrs;
	int next_idx = desc->next_wr_idx;
	struct ibv_send_wr *next_wr;

	if (next_idx >= MAX_SEND_WRS)
		return NULL;

	next_wr = &wrs[next_idx];
	next_wr->next = NULL;

	/* make a link from previous WR */
	if (next_idx > 0)
		wrs[next_idx - 1].next = next_wr;

	desc->next_wr_idx = ++next_idx;

	return next_wr;
}

static inline bool is_client()
{
	return (conf.server_name != NULL);
}

static volatile bool stop = false;
static volatile bool sq_drained = false;

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
	if (rc != xfer_size)
		fprintf(stderr, "Failed writing data during sock_sync_data\n");
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
		fprintf(stderr, "failed to post RR: rc %d\n", rc);

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

static void dereg_mr(struct ibv_mr **mr)
{
	if (*mr) {
		ibv_dereg_mr(*mr);
		*mr = NULL;
	}
}

int alloc_buffer(struct ibv_pd *pd, size_t size, struct buffer *buf)
{
	int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
		       IBV_ACCESS_REMOTE_WRITE;
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t page_mask = page_size - 1;
	/* align up to page size */
	size_t mem_size = (size + page_mask) & ~page_mask;

	memset(buf, 0, sizeof *buf);

	if (!size)
		return 0;

	buf->ptr = mmap(0, mem_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf->ptr == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	memset(buf->ptr, 0, size);

	buf->mr = ibv_reg_mr(pd, buf->ptr, size, mr_flags);
	if (!buf->mr) {
		perror("ibv_reg_mr");
		munmap(buf->ptr, mem_size);
		buf->ptr = NULL;
		return -1;
	}

	buf->size = size;
	buf->mem_size = mem_size;

	return 0;
}

void free_buffer(struct buffer *buf)
{
	dereg_mr(&buf->mr);

	if (buf->ptr && buf->ptr != MAP_FAILED) {
		munmap(buf->ptr, buf->mem_size);
		buf->ptr = NULL;
	}
	buf->size = 0;
	buf->mem_size = 0;
}

static int alloc_ind_buffer(struct buffer *orig_buffer, size_t offset,
			    size_t new_size, struct ind_buffer *buf)
{
	if (offset + new_size > orig_buffer->size) {
		return -ENOMEM;
	}

	buf->orig = orig_buffer;
	buf->offset = offset;
	buf->size = new_size;

	return 0;
}

static inline size_t get_buffer_size(struct buffer *buf)
{
	return buf->size;
}

static inline struct ibv_mr *get_buffer_mr(struct buffer *buf)
{
	return buf->mr;
}

static inline uint32_t get_buffer_rkey(struct buffer *buf)
{
	return buf->mr->rkey;
}

static inline uint32_t get_buffer_lkey(struct buffer *buf)
{
	return buf->mr->lkey;
}

static inline uint8_t *get_buffer_ptr(struct buffer *buf)
{
	return buf->ptr;
}

static inline uint64_t get_buffer_addr(struct buffer *buf)
{
	return (uintptr_t)buf->mr->addr;
}

static void free_ind_buffer(struct ind_buffer *buf)
{
	memset(buf, 0, sizeof(*buf));
}

static inline size_t get_ind_buffer_size(struct ind_buffer *buf)
{
	return get_buffer_size(buf->orig);
}

static inline struct ibv_mr *get_ind_buffer_mr(struct ind_buffer *buf)
{
	return get_buffer_mr(buf->orig);
}

static inline uint32_t get_ind_buffer_rkey(struct ind_buffer *buf)
{
	return get_buffer_rkey(buf->orig);
}

static inline uint32_t get_ind_buffer_lkey(struct ind_buffer *buf)
{
	return get_buffer_lkey(buf->orig);
}

static inline uint8_t *get_ind_buffer_ptr(struct ind_buffer *buf)
{
	return get_buffer_ptr(buf->orig) + buf->offset;
}

static inline uint64_t get_ind_buffer_addr(struct ind_buffer *buf)
{
	return get_buffer_addr(buf->orig) + buf->offset;
}

void fill_buffer(struct buffer *buf)
{
	int i, block_num;
	uint8_t *data = get_buffer_ptr(buf);
	int size = get_buffer_size(buf);

	block_num = size / (SERVER_DATA_SIZE + PI_SIZE);
	fprintf(stderr, "size %d block_num %d pi_size %d\n", size, block_num,
		PI_SIZE);

	memset(data, 0xA5, size);

	/* corrupt the first byte of buf */
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
		perror("ibv_exp_create_mr");

	return mr;
}

static int create_rx(struct resources *res)
{
	size_t max_msg_size;
	struct buffer *recv_buf = &res->recv_buf;
	int num_rx_descs = conf.queue_depth;
	size_t offset = 0;
	struct rx_desc *rx;
	int rc, i;

	max_msg_size = is_client() ? MSG_REP_MAX_SIZE : MSG_REQ_MAX_SIZE;

	rc = alloc_buffer(res->pd, max_msg_size * num_rx_descs,
			  recv_buf);
	if (rc)
		return rc;

	rx = calloc(num_rx_descs, sizeof(struct rx_desc));
	if (!rx) {
		rc = -ENOMEM;
		goto err_free_buf;
	}

	for (i = 0; i < num_rx_descs; i++, offset += max_msg_size) {
		struct rx_desc *desc = &rx[i];
		struct ibv_sge *sge = &desc->sge;
		struct ibv_recv_wr *wr = &desc->wr;

		rc = alloc_ind_buffer(recv_buf, offset, max_msg_size,
				      &desc->recv_buf);
		if (rc)
			goto err_free_rx;

		sge->addr = get_ind_buffer_addr(&desc->recv_buf);
		sge->length = get_ind_buffer_size(&desc->recv_buf);
		sge->lkey = get_ind_buffer_lkey(&desc->recv_buf);

		wr->sg_list = sge;
		wr->num_sge = 1;
		wr->next = NULL;
	}
	res->rx = rx;
	res->num_rx_descs = num_rx_descs;

	return 0;
err_free_rx:
	for (i--; i >= 0; i--) {
		struct rx_desc *desc = &rx[i];

		free_ind_buffer(&desc->recv_buf);
	}
	free(rx);
err_free_buf:
	free_buffer(recv_buf);
	res->rx = NULL;

	return rc;
}

static void destroy_rx(struct resources *res)
{
	int i;

	if (res->rx) {
		for (i = 0; i < res->num_rx_descs; i++) {
			free_ind_buffer(&res->rx[i].recv_buf);
		}
		free(res->rx);
		res->rx = NULL;
		res->num_rx_descs = 0;
	}

	free_buffer(&res->recv_buf);
}

static int create_tx(struct resources *res)
{
	size_t max_msg_size;
	/* +1 for stop request */
	int num_tx_descs = (conf.queue_depth + 1);
	struct buffer *send_buf = &res->send_buf;
	struct tx_desc *tx;
	size_t offset = 0;
	int rc, i;

	max_msg_size = is_client() ? MSG_REQ_MAX_SIZE : MSG_REP_MAX_SIZE;

	rc = alloc_buffer(res->pd, max_msg_size * num_tx_descs,
			  send_buf);
	if (rc)
		return rc;

	tx = calloc(num_tx_descs, sizeof(struct tx_desc));
	if (!tx) {
		rc = -ENOMEM;
		goto err_free_buf;
	}

	for (i = 0; i < num_tx_descs; i++, offset += max_msg_size) {
		struct tx_desc *desc = &tx[i];
		struct ibv_sge *sge = &desc->msg_sge;

		rc = alloc_ind_buffer(send_buf, offset, max_msg_size,
				      &desc->send_buf);
		if (rc)
			goto err_free_tx;

		sge->addr = get_ind_buffer_addr(&desc->send_buf);
		sge->length = get_ind_buffer_size(&desc->send_buf);
		sge->lkey = get_ind_buffer_lkey(&desc->send_buf);

		desc->sig_mr = create_sig_mr(res);
		if (!desc->sig_mr) {
			rc = -1;
			goto err_free_tx;
		}
	}

	res->tx = tx;
	res->num_tx_descs = num_tx_descs;

	return 0;
err_free_tx:
	for (i--; i >= 0; i--) {
		struct tx_desc *desc = &tx[i];

		free_ind_buffer(&desc->send_buf);
		if (desc->sig_mr)
			mlx5dv_destroy_mkey(desc->sig_mr);
	}
	free(tx);
err_free_buf:
	free_buffer(send_buf);
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
			free_ind_buffer(&desc->send_buf);
		}
		free(res->tx);
		res->tx = NULL;
		res->num_tx_descs = 0;
	}

	free_buffer(&res->send_buf);
}

static int create_tasks(struct resources *res)
{
	struct task *tasks;
	struct buffer *data_buf = &res->data_buf;
	size_t data_buf_size;
	int num_tasks = conf.queue_depth;
	size_t offset = 0;
	int i, qe, rc;

	if (is_client())
		data_buf_size = conf.nb * SERVER_DATA_SIZE;
	else
		data_buf_size = conf.nb * (SERVER_DATA_SIZE + PI_SIZE);

	rc = alloc_buffer(res->pd, data_buf_size * num_tasks, data_buf);
	if (rc)
		return rc;

	tasks = calloc(num_tasks, sizeof(struct task));
	if (!tasks) {
		rc = -ENOMEM;
		goto err_free_buf;
	}

	for (i = 0; i < num_tasks; i++, offset += data_buf_size) {
		struct task *task = &tasks[i];

		rc = alloc_ind_buffer(data_buf, offset, data_buf_size,
				      &task->data_buf);
		if (rc)
			goto err_free_tasks;
	}

	res->tasks = tasks;
	res->num_tasks = num_tasks;

	for (qe = 0; qe < conf.queue_depth; qe++) {
		struct task *task = get_task(res, qe);
		task->req_id = qe;
	}
	return 0;
err_free_tasks:
	for (i--; i >= 0; i--) {
		struct task *task = &tasks[i];

		free_ind_buffer(&task->data_buf);
	}
	free(tasks);
err_free_buf:
	free_buffer(data_buf);
	return rc;
}

static void destroy_tasks(struct resources *res)
{
	int i;

	if (res->tasks) {
		for (i = 0; i < res->num_tasks; i++) {
			free_ind_buffer(&res->tasks[i].data_buf);
		}
		free(res->tasks);
		res->tasks = NULL;
		res->num_tasks = 0;
	}
	free_buffer(&res->data_buf);
}

static void destroy_qp(struct ibv_qp *qp)
{
	if (qp && ibv_destroy_qp(qp))
		fprintf(stderr, "failed to destroy QP 0x%x\n", qp->qp_num);
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

int check_sig_mr(struct mlx5dv_mkey *mkey)
{
	struct mlx5dv_mkey_err err_info;
	int rc;

	rc = mlx5dv_mkey_check(mkey, &err_info);
	if (rc) {
		fprintf(stderr, "check mr status failed\n");
		return rc;
	}

	rc = err_info.err_type;
	switch (rc) {
	case MLX5DV_MKEY_NO_ERR:
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_REFTAG:
		fprintf(stderr, "bad block reftag error has been detected\n");
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_APPTAG:
		fprintf(stderr, "bad block apptag error has been detected\n");
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD:
		fprintf(stderr, "bad block guard error has been detected\n");
		break;
	default:
		fprintf(stderr, "Unknown error has been detected\n");
		break;
	}

	if (rc)
		fprintf(stdout, "mr status: %s(%d) expected_value %lu "
				"actual_value %lu offset %lu\n",
			"SIG ERROR", rc, err_info.err.sig.expected_value,
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
	/* QP events */
	case IBV_EVENT_QP_FATAL:
		fprintf(stdout, "QP fatal event for QP with handle %p\n",
			event->element.qp);
		break;
	case IBV_EVENT_QP_REQ_ERR:
		fprintf(stdout, "QP Requestor error for QP with handle %p\n",
			event->element.qp);
		break;
	case IBV_EVENT_QP_ACCESS_ERR:
		fprintf(stdout, "QP access error event for QP with handle %p\n",
			event->element.qp);
		break;
	case IBV_EVENT_COMM_EST:
		fprintf(stdout,
			"QP communication established event for QP with handle "
			"%p\n",
			event->element.qp);
		break;
	case IBV_EVENT_SQ_DRAINED:
		fprintf(stdout,
			"QP Send Queue drained event for QP with handle %p\n",
			event->element.qp);
		break;
	case IBV_EVENT_PATH_MIG:
		fprintf(
		    stdout,
		    "QP Path migration loaded event for QP with handle %p\n",
		    event->element.qp);
		break;
	case IBV_EVENT_PATH_MIG_ERR:
		fprintf(stdout,
			"QP Path migration error event for QP with handle %p\n",
			event->element.qp);
		break;
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		fprintf(stdout,
			"QP last WQE reached event for QP with handle %p\n",
			event->element.qp);
		break;

	/* CQ events */
	case IBV_EVENT_CQ_ERR:
		fprintf(stdout, "CQ error for CQ with handle %p\n",
			event->element.cq);
		break;

	/* SRQ events */
	case IBV_EVENT_SRQ_ERR:
		fprintf(stdout, "SRQ error for SRQ with handle %p\n",
			event->element.srq);
		break;
	case IBV_EVENT_SRQ_LIMIT_REACHED:
		fprintf(stdout,
			"SRQ limit reached event for SRQ with handle %p\n",
			event->element.srq);
		break;

	/* Port events */
	case IBV_EVENT_PORT_ACTIVE:
		fprintf(stdout, "Port active event for port number %d\n",
			event->element.port_num);
		break;
	case IBV_EVENT_PORT_ERR:
		fprintf(stdout, "Port error event for port number %d\n",
			event->element.port_num);
		break;
	case IBV_EVENT_LID_CHANGE:
		fprintf(stdout, "LID change event for port number %d\n",
			event->element.port_num);
		break;
	case IBV_EVENT_PKEY_CHANGE:
		fprintf(stdout, "P_Key table change event for port number %d\n",
			event->element.port_num);
		break;
	case IBV_EVENT_GID_CHANGE:
		fprintf(stdout, "GID table change event for port number %d\n",
			event->element.port_num);
		break;
	case IBV_EVENT_SM_CHANGE:
		fprintf(stdout, "SM change event for port number %d\n",
			event->element.port_num);
		break;
	case IBV_EVENT_CLIENT_REREGISTER:
		fprintf(stdout, "Client reregister event for port number %d\n",
			event->element.port_num);
		break;

	/* RDMA device events */
	case IBV_EVENT_DEVICE_FATAL:
		fprintf(stdout, "Fatal error event for device %s\n",
			ibv_get_device_name(ctx->device));
		break;

	default:
		fprintf(stdout, "Unknown event (%d)\n", event->event_type);
	}
}

/******************************************************************************
 * Function: poll_completion
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
 * Poll the completion queue for a single event. This function will continue to
 * poll the queue until MAX_POLL_CQ_TIMEOUT milliseconds have passed.
 *
 ******************************************************************************/
static int poll_completion(struct resources *res)
{
	unsigned long start_time_msec;
	unsigned long cur_time_msec;
	struct timeval cur_time;
	struct ibv_wc wc;
	int poll_result;
	int rc = 0;

	/* poll the completion for a while before giving up of doing it .. */
	gettimeofday(&cur_time, NULL);
	start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	do {
		poll_result = ibv_poll_cq(res->cq, 1, &wc);
		gettimeofday(&cur_time, NULL);
		cur_time_msec =
		    (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);

		server_check_async_event(res);
		if (sq_drained)
			return 1;

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
		/** rc = 1; */
	} else {
		/* CQE found */
		/** fprintf( */
		/**     stdout, */
		/**     "completion was found in CQ with status 0x%x, opcode %u\n", */
		/**     wc.status, wc.opcode); */
		/* check the completion status (here we don't care about the
		 * completion opcode */
		if (wc.status != IBV_WC_SUCCESS) {
			fprintf(stderr, "got bad completion with status: 0x%x, "
					"vendor syndrome: 0x%x\n",
				wc.status, wc.vendor_err);
			rc = 1;
		}
	}
	return rc;
}

static inline void init_send_wr(struct resources *res, uint64_t req_id,
				uint64_t send_flags)
{
	struct tx_desc *desc = get_tx_desc(res, req_id);
	struct ibv_send_wr *wr = next_send_wr(desc);

	memset(wr, 0, sizeof(*wr));
	wr->opcode = IBV_WR_SEND;
	wr->send_flags = send_flags;
	wr->sg_list = &desc->msg_sge;
	wr->num_sge = 1;
	wr->wr_id = req_id;
}

static inline int post_send(struct ibv_qp *qp, struct tx_desc *desc)
{
	struct ibv_send_wr *bad_wr;
	int rc;

	rc = ibv_post_send(qp, first_send_wr(desc), &bad_wr);
	desc->next_wr_idx = 0;

	return rc;
}

int configure_sig_mkey(struct resources *res,
		       struct mlx5dv_sig_block_attr *sig_attr,
		       struct task *task) {
	struct ibv_qp *qp;
	struct ibv_qp_ex *qpx;
	struct mlx5dv_qp_ex *dv_qp;
	struct mlx5dv_mkey *mkey;
	uint64_t data_addr;
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

	ibv_wr_start(qpx);
	qpx->wr_id = 0;
	qpx->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

	mlx5dv_wr_mkey_configure(dv_qp, mkey, 3, &conf_attr);
	mlx5dv_wr_set_mkey_access_flags(dv_qp, access_flags);

	data_addr = get_ind_buffer_addr(&task->data_buf);

	sge.addr = data_addr;
	sge.length = conf.nb * (SERVER_DATA_SIZE + PI_SIZE);
	sge.lkey = get_ind_buffer_lkey(&task->data_buf);

	mlx5dv_wr_set_mkey_layout_list(dv_qp, 1, &sge);

	mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);

	return ibv_wr_complete(qpx);
}

static int reg_data_mrs(struct resources *res, struct task *task)
{
	union {
		struct mlx5dv_sig_t10dif t10dif;
		struct mlx5dv_sig_crc crc;
	} mem_sig;
	struct mlx5dv_sig_block_domain mem;
	struct mlx5dv_sig_block_attr sig_attr = {
		.mem = &mem,
		.wire = NULL,
		.check_mask = MLX5DV_SIG_CHECK_T10DIF_GUARD |
			      MLX5DV_SIG_CHECK_T10DIF_APPTAG |
			      MLX5DV_SIG_CHECK_T10DIF_REFTAG,
	};
	int rc;

	set_sig_domain_t10dif_type3(&mem, &mem_sig);

	rc = configure_sig_mkey(res, &sig_attr, task);
	if (rc) {
		fprintf(stderr, "configuring sig MR failed\n");
		return rc;
	}

	rc = poll_completion(res);
	if (rc) {
		fprintf(stderr, "poll completion failed\n");
	}

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
	destroy_qp(res->qp);
	destroy_tasks(res);
	destroy_tx(res);
	destroy_rx(res);
	if (res->cq) {
		if (ibv_destroy_cq(res->cq)) {
			fprintf(stderr, "failed to destroy CQ\n");
			rc = 1;
		}
		res->cq = NULL;
	}
	if (res->pd) {
		if (ibv_dealloc_pd(res->pd)) {
			fprintf(stderr, "failed to deallocate PD\n");
			rc = 1;
		}
		res->pd = NULL;
	}
	if (res->ib_ctx) {
		if (ibv_close_device(res->ib_ctx)) {
			fprintf(stderr, "failed to close device context\n");
			rc = 1;
		}
		res->ib_ctx = NULL;
	}

	if (res->sock >= 0) {
		if (close(res->sock)) {
			fprintf(stderr, "failed to close socket\n");
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
		fprintf(
		    stderr,
		    "failed to change file descriptor of async event queue\n");

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

	/* if client side */
	if (is_client()) {
		res->sock = sock_connect(conf.server_name, conf.tcp_port);
		if (res->sock < 0) {
			fprintf(stderr, "failed to establish TCP connection to "
					"server %s, port %d\n",
				conf.server_name, conf.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	} else {
		fprintf(stdout, "waiting on port %d for TCP connection\n",
			conf.tcp_port);
		res->sock = sock_connect(NULL, conf.tcp_port);
		if (res->sock < 0) {
			fprintf(stderr, "failed to establish TCP connection "
					"with client on port %d\n",
				conf.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	}

	/* TCP connection was established, searching for IB devices in host */
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
		if (!conf.dev_name) {
			conf.dev_name =
			    strdup(ibv_get_device_name(dev_list[i]));
			fprintf(
			    stdout,
			    "device not specified, using first one found: %s\n",
			    conf.dev_name);
		}
		if (!strcmp(ibv_get_device_name(dev_list[i]), conf.dev_name)) {
			ib_dev = dev_list[i];
			break;
		}
	}
	/* if the device wasn't found in host */
	if (!ib_dev) {
		fprintf(stderr, "IB device %s wasn't found\n", conf.dev_name);
		rc = 1;
		goto resources_create_exit;
	}
	/* get device handle */
	if (mlx5dv_is_supported(ib_dev)) {
		fprintf(stdout, "device %s support mlx5dv\n", conf.dev_name);
		dv_attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;
		res->ib_ctx = mlx5dv_open_device(ib_dev, &dv_attr);
	} else {
		res->ib_ctx = ibv_open_device(ib_dev);
	}
	if (!res->ib_ctx) {
		fprintf(stderr, "failed to open device %s errno %d\n",
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
		fprintf(stderr, "ibv_exp_query_device on device %s failed\n",
			ibv_get_device_name(res->ib_ctx->device));
		rc = 1;
		goto resources_create_exit;
	}

	/* query port properties */
	if (ibv_query_port(res->ib_ctx, conf.ib_port, &res->port_attr)) {
		fprintf(stderr, "ibv_query_port on port %u failed\n",
			conf.ib_port);
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

	/* number of send WRs + one recv WR */
	res->cq = ibv_create_cq(res->ib_ctx, CQ_SIZE, NULL, NULL, 0);
	if (!res->cq) {
		fprintf(stderr, "failed to create CQ with %u entries\n",
			CQ_SIZE);
		rc = 1;
		goto resources_create_exit;
	}

	rc = create_tx(res);
	if (rc) {
		goto resources_create_exit;
	}
	rc = create_rx(res);
	if (rc) {
		goto resources_create_exit;
	}
	rc = create_tasks(res);
	if (rc) {
		goto resources_create_exit;
	}

	if (is_server())
		fill_buffer(&res->data_buf);

	res->qp = create_qp(res);
	if (!res->qp) {
		fprintf(stderr, "failed to create QP\n");
		rc = 1;
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
	attr.path_mtu = conf.mtu;
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
		fprintf(stderr, "failed to modify QP state to RTR\n");
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
		fprintf(stderr, "failed to modify QP state to RTR\n");
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
static int modify_qp_to_rts(struct ibv_qp *qp, int flags)
{
	struct ibv_qp_attr attr;
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
		fprintf(stderr, "failed to modify QP state to RTS, rc %d\n", rc);
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
			fprintf(stderr,
				"could not get gid for port %d, index %d\n",
				conf.ib_port, conf.gid_idx);
			return rc;
		}
	} else
		memset(&my_gid, 0, sizeof my_gid);

	local_con_data.qp_num = htonl(res->qp->qp_num);
	local_con_data.lid = htons(res->port_attr.lid);
	memcpy(local_con_data.gid, &my_gid, 16);
	fprintf(stdout, "\nLocal LID = 0x%x\n", res->port_attr.lid);

	if (sock_sync_data(res->sock, sizeof(struct cm_con_data_t),
			   (char *)&local_con_data, (char *)&tmp_con_data)) {
		fprintf(stderr,
			"failed to exchange connection data between sides\n");
		rc = 1;
		goto connect_qp_exit;
	}
	remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
	remote_con_data.lid = ntohs(tmp_con_data.lid);
	memcpy(remote_con_data.gid, tmp_con_data.gid, 16);
	/* save the remote side attributes, we will need it for the post SR */
	res->remote_props = remote_con_data;
	fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
	fprintf(stdout, "Remote QP = { 0x%x }\n", remote_con_data.qp_num);

	if (conf.gid_idx >= 0) {
		uint8_t *p = remote_con_data.gid;
		fprintf(stdout, "Remote GID = "
				"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%"
				"02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
			p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
	}

	/* modify the QP to init */
	rc = modify_qp_to_init(res->qp);
	if (rc) {
		fprintf(stderr, "change QP 0x%x state to INIT failed\n",
			res->qp->qp_num);
		goto connect_qp_exit;
	}

	rc = post_recv_all(res);
	if (rc) {
		fprintf(stderr, "failed to post RR\n");
		goto connect_qp_exit;
	}

	/* modify the QP to RTR */
	rc = modify_qp_to_rtr(res->qp, remote_con_data.qp_num,
			      remote_con_data.lid, remote_con_data.gid);
	if (rc) {
		fprintf(
		    stderr,
		    "failed to modify QP 0x%x remote QP 0x%x state to RTR\n",
		    res->qp->qp_num, remote_con_data.qp_num);
		goto connect_qp_exit;
	}
	int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
		    IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	rc = modify_qp_to_rts(res->qp, flags);
	if (rc) {
		fprintf(stderr, "failed to modify QP 0x%x state to RTS\n",
			res->qp->qp_num);
		goto connect_qp_exit;
	}
	fprintf(stdout, "QP state was change to RTS\n");

	/* sync to make sure that both sides are in states that they can connect
	 * to prevent packet loose
	 */
	if (sock_sync_data(res->sock, 1, "Q",
			   &temp_char)) /* just send a dummy char back
					   and forth */
	{
		fprintf(stderr, "sync error after QP are were moved to RTS\n");
		rc = 1;
	}
connect_qp_exit:
	return rc;
}

static int client_send_req(struct resources *res,
			   uint64_t req_id,
			   enum msg_types type)
{
	struct tx_desc *desc;
	struct task *task;
	uint8_t *msg;
	struct msg_req_hdr *hdr;
	size_t msg_length;
	struct iov *iov;
	int iov_size;
	struct ibv_sge *sge;

	desc = get_tx_desc(res, req_id);
	msg = get_ind_buffer_ptr(&desc->send_buf);

	switch (type) {
	case MSG_TYPE_READ_REQ:
	case MSG_TYPE_WRITE_REQ:
	case MSG_TYPE_STOP_REQ:
		break;
	default:
		return -EINVAL;
	}

	hdr = (struct msg_req_hdr *)msg;
	msg += sizeof(*hdr);
	msg_length = sizeof(*hdr);

	hdr->type = htons(type);
	hdr->id = htonll(req_id);
	hdr->iov_size = htons(1);
	hdr->inline_data_size = htonl(0);

	if (MSG_TYPE_STOP_REQ != type) {
		iov = (struct iov *)msg;

		task = get_task(res, req_id);

		iov->addr = htonll(get_ind_buffer_addr(&task->data_buf));
		iov->length = htonl(conf.nb * SERVER_DATA_SIZE);
		iov->rkey = htonl(get_ind_buffer_rkey(&task->data_buf));
		iov_size = 1;

		msg_length += sizeof(*iov) * iov_size;
	}

	sge = &desc->msg_sge;
	sge->addr = get_ind_buffer_addr(&desc->send_buf);
	sge->length = msg_length;
	sge->lkey = get_ind_buffer_lkey(&desc->send_buf);

	init_send_wr(res, req_id, IBV_SEND_SIGNALED);

	return post_send(get_qp(res), desc);
}

static int client(struct resources *res)
{
	int req, i, rc;
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
		perror("clock_gettime");
		goto err_exit;
	}

	while (!stop) {
		rc = ibv_poll_cq(res->cq, MAX_WC_PER_POLL, wc);
		res->polls_counter++;
		if (!rc)
			continue;
		if (rc < 0) {
			perror("ibv_poll_cq");
			break;
		}
		res->comps_counter += rc;

		for (i = 0; i < rc && !stop; ++i) {
			int result;

			if (wc[i].status != IBV_WC_SUCCESS) {
				fprintf(stderr, "failed wr_id %lu, opcode %d\n",
					wc[i].wr_id, wc[i].opcode);
				stop = true;
				break;
			}
			req_id = wc[i].wr_id;
			switch (wc[i].opcode) {
			case IBV_WC_SEND:
				/* ignore successfull send completions */
				/** fprintf(stdout, "WC wr_id %lu, opcode SEND\n ", */
				/**                 wc[i].wr_id); */
				break;
			case IBV_WC_RECV:
				/** fprintf(stdout, "WC wr_id %lu, opcode RECV\n ", */
				/**                 wc[i].wr_id); */
				desc = get_rx_desc(res, req_id);

				res->io_counter++;

				msg = get_ind_buffer_ptr(&desc->recv_buf);
				hdr = (struct msg_rep_hdr *)msg;
				status = ntohs(hdr->status);
				if (status == MSG_REP_STATUS_FAIL) {
					fprintf(stdout, "Got failure response "
							"with wr_id %lu\n",
						ntohll(hdr->id));
				}

				result = post_recv(get_qp(res), desc);
				if (result) {
					fprintf(stdout, "WC wr_id %lu, opcode "
							"RECV, post_recv "
							"result %d\n",
						wc[i].wr_id, result);
					stop = true;
					break;
				}

				result = client_send_req(res, req_id, req_type);
				if (result) {
					fprintf(stdout, "WC wr_id %lu, opcode "
							"RECV, client_send_req "
							"result %d\n",
						wc[i].wr_id, result);
					stop = true;
				}
				break;
			default:
				fprintf(stderr, "unknown WC opcode %d\n",
					wc[i].opcode);
				stop = true;
			}
		}
	}
	req_id = conf.queue_depth;
	rc = client_send_req(res, req_id, MSG_TYPE_STOP_REQ);
	if (rc) {
		fprintf(stderr, "Failed to send stop request\n");
	}
	rc = clock_gettime(CLOCK_MONOTONIC_COARSE, &end_time);
	if (rc) {
		perror("clock_gettime");
		goto err_exit;
	}
	iops = (end_time.tv_sec - start_time.tv_sec) * 1000;
	iops += (end_time.tv_nsec - start_time.tv_nsec) / 1000000;
	if (iops)
		iops = (res->io_counter * 1000) / iops;
	fprintf(stdout, "IOps : %lu\n", iops);

err_exit:
	flush_qp(res);

	return rc;
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
		fprintf(stderr, "received message is too short, length %lu\n",
			msg_len);
		return NULL;
	}

	hdr = (struct msg_req_hdr *)msg;
	msg += sizeof(*hdr);
	msg_len -= sizeof(*hdr);

	req_type = ntohs(hdr->type);

	if (req_type == MSG_TYPE_STOP_REQ) {
		stop = true;
		fprintf(stdout, "Got stop request\n");
		return NULL;
	}

	req_id = ntohll(hdr->id);
	if (req_id > conf.queue_depth) {
		fprintf(stderr, "invalid request id(%lu) qd %d\n", req_id,
			conf.queue_depth);
		return NULL;
	}
	task = get_task(res, req_id);
	if (task->status != TASK_STATUS_FREE) {
		fprintf(stderr, "request id(%lu) is busy\n", req_id);
		return NULL;
	}

	switch (req_type) {
	case MSG_TYPE_WRITE_REQ:
		task->type = TASK_TYPE_WRITE;
		break;
	case MSG_TYPE_READ_REQ:
		task->type = TASK_TYPE_READ;
		break;
	default:
		fprintf(stderr, "unknown request type(%u)\n", req_type);
		return NULL;
	}

	if (hdr->inline_data_size) {
		fprintf(stderr, "inline data is not implemented\n");
		return NULL;
	}

	iov_size = ntohs(hdr->iov_size);
	if (iov_size > IOV_MAX_SIZE) {
		fprintf(stderr, "invalid iov_size %u\n", iov_size);
		return NULL;
	}
	task->iov_size = iov_size;

	if (msg_len < (sizeof(*iov) * iov_size)) {
		fprintf(stderr, "invalid message, iov_size\n");
		return NULL;
	}
	iov = (struct iov *)msg;
	msg_len -= sizeof(*iov) * iov_size;

	task->data_len = 0;
	for (i = 0; i < iov_size; i++) {
		struct iov *src = &iov[i];
		struct iov *dst = &task->iov[i];

		dst->addr = ntohll(src->addr);
		dst->length = ntohl(src->length);
		dst->rkey = ntohl(src->rkey);
		task->data_len += dst->length;
	}
	task->status = TASK_STATUS_INITED;

	return task;
}

static inline int server_send_reply(struct resources *res,
				    struct task *task,
				    enum msg_rep_status status)
{
	struct tx_desc *desc;
	enum msg_types reply_type;
	uint8_t *msg;
	struct msg_rep_hdr *hdr;
	size_t msg_length;
	struct ibv_sge *sge;

	desc = get_tx_desc(res, task->req_id);

	switch (task->type) {
	case TASK_TYPE_READ:
		reply_type = MSG_TYPE_READ_REP;
		break;
	case TASK_TYPE_WRITE:
		reply_type = MSG_TYPE_WRITE_REP;
		break;
	default:
		fprintf(stderr, "unknown task type %d\n", task->type);
		return -EINVAL;
	}

	msg = get_ind_buffer_ptr(&desc->send_buf);
	hdr = (struct msg_rep_hdr *)msg;
	msg += sizeof(*hdr);
	msg_length = sizeof(*hdr);

	hdr->type = htons(reply_type);
	hdr->id = htonll(task->req_id);
	hdr->status = htons(status);
	hdr->inline_data_size = htonl(0);

	sge = &desc->msg_sge;
	sge->addr = get_ind_buffer_addr(&desc->send_buf);
	sge->length = msg_length;
	sge->lkey = get_ind_buffer_lkey(&desc->send_buf);

	init_send_wr(res, task->req_id, IBV_SEND_SIGNALED);
	task->status = TASK_STATUS_FREE;

	return post_send(get_qp(res), desc);
}

static void server_rdma_write(struct resources *res, struct task *task) {
	struct tx_desc *desc = get_tx_desc(res, task->req_id);
	struct ibv_send_wr *wr = next_send_wr(desc);
	struct ibv_sge *sge = &desc->sge;

	sge->addr = 0;
	/* length on wire domain */
	sge->length = conf.nb * SERVER_DATA_SIZE;
	sge->lkey = desc->sig_mr->lkey;

	/** fill_wr: */
	memset(wr, 0, sizeof(*wr));
	wr->sg_list = sge;
	wr->num_sge = 1;
	wr->opcode = IBV_WR_RDMA_WRITE;
	wr->wr_id = task->req_id;
	wr->wr.rdma.remote_addr = task->iov[0].addr;
	wr->wr.rdma.rkey = task->iov[0].rkey;
}

static inline int server_handle_read_task(struct resources *res,
					  struct task *task)
{
	int rc;

	rc = reg_data_mrs(res, task);
	if (rc) {
		if (sq_drained) {
			task->status = TASK_STATUS_FREE;
			/** fprintf(stderr, "failed to reg mr due to sq_drained %lu\n", task->req_id); */
			return 0;
		}
		fprintf(stderr, "failed to reg mr without sq_drained %lu\n", task->req_id);
		return rc;
	}

	server_rdma_write(res, task);

	/* send reply with rdma write */
	return server_send_reply(res, task, MSG_REP_STATUS_OK);
}

static inline int server_handle_write_task(struct resources *res,
					   struct task *task)
{
	fprintf(stderr, "write task is not implemented\n");

	return -1;
}

static inline int server_handle_async_event(struct resources *res)
{
	int i, wr_num, rc = 0;
	int flags = IBV_QP_STATE;
	struct ibv_qp *qp;
	struct task *task;

	struct tx_desc *desc;

	struct ibv_qp_ex *qpx;
	struct mlx5dv_qp_ex *dv_qp;

	qp = res->qp;
	qpx = ibv_qp_to_qp_ex(qp);
	dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);

	for (i = 0; i < conf.queue_depth; i++) {
		desc = get_tx_desc(res, i);
		if (check_sig_mr(desc->sig_mr)) {
			wr_num = mlx5dv_qp_cancel_posted_send_wrs(dv_qp, i);
			if (wr_num) {
				task = get_task(res, i);
				task->status =
				    TASK_STATUS_WR_CANCELED_WITH_ERR;
			}
		}
	}
	modify_qp_to_rts(qp, flags);

	sq_drained = false;

	return rc;
}

static inline int server_check_async_event(struct resources *res)
{
	int rc = 0;
	struct ibv_async_event event;
	rc = ibv_get_async_event(res->ib_ctx, &event);
	if (rc) {
		return -1;
	}
	print_async_event(res->ib_ctx, &event);
	if (IBV_EVENT_SQ_DRAINED == event.event_type) {
		sq_drained = true;
	}
	ibv_ack_async_event(&event);

	return rc;
}

static inline int server_handle_rdma_write_comp(struct resources *res,
						struct ibv_wc *wc)
{
	struct tx_desc *desc = get_tx_desc(res, wc->wr_id);
	struct task *task = get_task(res, wc->wr_id);
	int rc = 0;
	enum msg_rep_status sig_status;

	rc = check_sig_mr(desc->sig_mr);

	sig_status = rc ? MSG_REP_STATUS_FAIL : MSG_REP_STATUS_OK;
	rc = server_send_reply(res, task, sig_status);

	return 0;
}

static inline int server_handle_request(struct resources *res,
					struct ibv_wc *wc)
{
	struct rx_desc *desc;
	struct task *task;
	uint8_t *msg;
	unsigned msg_len;
	int rc;

	if (sq_drained) {
		// In this example, only 1 QP is uesed, 
		// qp is now in SQ_DRAINED status,
		// traffic should be stopped.
		fprintf(stderr, "do not send data on %lu when SQD\n",
			wc->wr_id);
		return 0;
	}

	desc = get_rx_desc(res, wc->wr_id);
	msg = get_ind_buffer_ptr(&desc->recv_buf);
	msg_len = wc->byte_len;

	task = server_init_task(res, msg, msg_len);
	if (!task)
		return -1;

	rc = post_recv(get_qp(res), desc);
	if (rc)
		return -1;

	switch (task->type) {
	case TASK_TYPE_READ:
		rc = server_handle_read_task(res, task);
		break;
	case TASK_TYPE_WRITE:
		rc = server_handle_write_task(res, task);
		break;
	default:
		rc = -1;
	}

	return rc;
}

static inline int server_handle_wc(struct resources *res, struct ibv_wc *wc)
{
	int rc = 0;
	struct task *task = get_task(res, wc->wr_id);

	if (wc->status != IBV_WC_SUCCESS) {
		fprintf(stderr, "failed WR id %lu, opcode %d\n", wc->wr_id,
			wc->opcode);
		return -1;
	}

	switch (task->status) {
	case TASK_STATUS_WR_CANCELED_WITH_ERR:
		fprintf(
		    stdout,
		    "wc opcode %d req_id %lu send reply with error response\n",
		    wc->opcode, task->req_id);
		server_send_reply(res, task, MSG_REP_STATUS_FAIL);
		return 0;
	default:
		break;
	}

	switch (wc->opcode) {
	case IBV_WC_RDMA_READ:
		/** fprintf(stdout, "WC wr_id %lu, opcode %d\n", */
		/**         wc->wr_id, wc->opcode); */
		break;
	case IBV_WC_RDMA_WRITE:
		/** fprintf(stdout, "WC wr_id %lu, opcode %d\n", */
		/**         wc->wr_id, wc->opcode); */
		rc = server_handle_rdma_write_comp(res, wc);
		break;
	case IBV_WC_SEND:
		/* ignore successfull send completions */
		/** fprintf(stdout, "WC wr_id %lu, opcode SEND\n", */
		/**         wc->wr_id); */
		break;
	case IBV_WC_RECV:
		/** fprintf(stdout, "WC wr_id %lu, opcode RECV(%d), status 0x%x\n", */
		/**         wc->wr_id, wc->opcode, wc->status); */
		rc = server_handle_request(res, wc);
		break;
	case IBV_WC_DRIVER1:
		// It's expected when mkey_configure() with the signal flag, or
		/** fprintf(stdout, "WC wr_id %lu, opcode %d\n", */
		/**         wc->wr_id, wc->opcode); */
		break;
	default:
		fprintf(stderr, "unknown WC opcode %d\n", wc->opcode);
		rc = -1;
	}

	return rc;
}

static int server(struct resources *res) {
	struct ibv_wc wc[MAX_WC_PER_POLL];
	int rc, i, count = CQ_SIZE;
	bool first;
	struct timespec start_ts, end_ts, first_ts;

	while (!stop) {
		server_check_async_event(res);
		rc = ibv_poll_cq(res->cq, MAX_WC_PER_POLL, wc);
		res->polls_counter++;
		if (!rc) {
			// 1. got SQ Drained event, poll all pending CQ
			// 2. cancel WR with signature error
			// 3. change QP to RTS
			if (sq_drained) {
				server_handle_async_event(res);
				count = CQ_SIZE;
			}
			continue;
		}

		if (rc < 0) {
			perror("ibv_poll_cq");
			break;
		}

		if (sq_drained) {
			// 1. got SQ Drained event, poll all pending CQ
			count -= rc;
		}
		if (sq_drained && count <= 0) {
			// 2. cancel WR with signature error
			// 3. change QP to RTS
			server_handle_async_event(res);
			count = CQ_SIZE;
		}

		res->comps_counter += rc;
		clock_gettime(CLOCK_MONOTONIC, &start_ts);
		if (!first) {
			first_ts = start_ts;
			first = true;
		}
		for (i = 0; i < rc; ++i) {
			if (0 != server_handle_wc(res, &wc[i])) {
				stop = true;
				break;
			}
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

	return 0;
}

static void print_config(void) {
	fprintf(stdout, " ------------------------------------------------\n");
	fprintf(stdout, " Device name : \"%s\"\n", conf.dev_name);
	fprintf(stdout, " IB port : %u\n", conf.ib_port);
	if (conf.server_name)
		fprintf(stdout, " IP : %s\n", conf.server_name);

	fprintf(stdout, " TCP port : %u\n", conf.tcp_port);
	if (conf.gid_idx >= 0)
		fprintf(stdout, " GID index : %u\n", conf.gid_idx);

	fprintf(stdout, " Block size : %u\n", SERVER_DATA_SIZE);
	fprintf(stdout, " I/O size : %d\n", conf.nb * SERVER_DATA_SIZE);
	fprintf(stdout, " Queue depth : %d\n", conf.queue_depth);
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

static void usage(const char *argv0) {
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, " %s start a server and wait for connection\n", argv0);
	fprintf(stdout, " %s <host> connect to server at <host>\n", argv0);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, " -h, --help                   print this message\n");
	fprintf(stdout, " -p, --port <port>            listen on/connect to "
			"port <port> (default 18515)\n");
	fprintf(stdout, " -d, --ib-dev <dev>           use IB device <dev> "
			"(default first device found)\n");
	fprintf(stdout, " -i, --ib-port <port>         use port <port> of IB "
			"device (default 1)\n");
	fprintf(stdout,
		" -g, --gid-idx <gid index>    gid index to be used in GRH "
		"(default not used)\n");
	fprintf(stdout, " -n, --number-of-blocks <NB>  Number of blocks per "
			"RDMA operation (default 8)\n");
	fprintf(stdout, " -q, --queue-depth <num>      number of simultaneous "
			"requests per QP"
			" that a client can send to the server.\n");
	fprintf(stdout, " -t, --test-time <seconds>    test duration in "
			"seconds (default 10)\n");
	fprintf(stdout,
		" -m, --mtu <1024|2048|4096>   set MTU (default 1024).\n");
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
	unsigned long mtu;
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
			{ .name = "mtu",		.has_arg = 1, .val = 'm' },
			{ .name = NULL,			.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "hp:d:i:g:n:s:q:t:m", long_options,
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
		case 'm':
			mtu = strtoul(optarg, NULL, 0);
			switch (mtu) {
			case 1024:
				conf.mtu = IBV_MTU_1024;
				break;
			case 2048:
				conf.mtu = IBV_MTU_2048;
				break;
			case 4096:
				conf.mtu = IBV_MTU_4096;
				break;
			default:
				fprintf(stderr, "%s is not a valid MTU\n",
					optarg);
				return 1;
			}
			/** conf.ignore_trans_crc = strtoul(optarg, NULL, 0); */
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

	if (resources_create(&res)) {
		fprintf(stderr, "failed to create resources\n");
		goto main_exit;
	}

	if (connect_qp(&res)) {
		fprintf(stderr, "failed to connect QP\n");
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

	fprintf(stdout, "Polls %lu, completions %lu, comps/poll %.1f\n",
		res.polls_counter, res.comps_counter,
		(double)res.comps_counter / res.polls_counter);
	if (!is_client()) {
		fprintf(stdout, "Busy time %lu ns, test time %lu ns, busy "
				"percent %.2f, time/comp %lu ns\n",
			res.busy_time, res.test_time,
			(double)res.busy_time /
			    ((uint64_t)conf.time * 1000000000) * 100,
			res.busy_time / res.comps_counter);
	}
main_exit:
	if (resources_destroy(&res)) {
		fprintf(stderr, "failed to destroy resources\n");
		rc = 1;
	}
	if (conf.dev_name)
		free((char *)conf.dev_name);
	fprintf(stdout, "\ntest result is %d\n", rc);

	return rc;
}
