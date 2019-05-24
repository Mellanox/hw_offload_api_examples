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
#include <fcntl.h>
#include <unistd.h>

/* poll CQ timeout in millisec (2 seconds) */
#define MAX_POLL_CQ_TIMEOUT 2000

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
	return bswap_64(x);
}
static inline uint64_t ntohll(uint64_t x)
{
	return bswap_64(x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
	return x;
}
static inline uint64_t ntohll(uint64_t x)
{
	return x;
}
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

enum sig_mode {
	SIG_MODE_INSERT,
	SIG_MODE_CHECK,
	SIG_MODE_STRIP,
};

struct signature_ops;

/* structure of test parameters */
struct config_t {
	const char *dev_name;	/* IB device name */
	char *server_name;	/* server host name */
	u_int32_t tcp_port;	/* server TCP port */
	int ib_port;		/* local IB port to work with */
	int gid_idx;		/* gid index to use */
	int block_size;
	int nb;
	int interleave;
	const struct signature_ops *sig;
	int pipeline;
	int corrupt_data;
};

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t {
	uint32_t qp_num;
	uint16_t lid;
	uint8_t gid[16];
} __attribute__((packed));

enum msg_types {
	MSG_TYPE_WRITE_REQ = 0,
	MSG_TYPE_WRITE_REP,
	MSG_TYPE_READ_REQ,
	MSG_TYPE_READ_REP,
	MSG_TYPE_CLOSE_CONN,
};

enum msg_rep_status {
	MSG_REP_STATUS_OK = 0,
	MSG_REP_STATUS_FAIL,
};

struct msg_t {
	uint8_t type;
	union {
		struct {
			uint64_t addr; /* Buffer address */
			uint32_t rkey; /* Remote key */
		} req;
		struct {
			uint32_t status;
		} rep;
	} data;
} __attribute__((packed));
#define MSG_SIZE (sizeof(struct msg_t))

/* structure of system resources */
struct resources {
	struct ibv_device_attr device_attr;
	/* Device attributes */
	struct ibv_port_attr port_attr;
	struct cm_con_data_t remote_props; /* values to connect to remote side */
	struct ibv_context *ib_ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_exp_wc wc;

	struct ibv_mr *send_mr;	/* MR for send buffer */
	struct ibv_mr *recv_mr;	/* MR for recv buffer */
	struct ibv_mr *data_mr;	/* MR for data buffer */
	struct ibv_mr *pi_mr;	/* MR for protection information buffer */
	struct ibv_mr *sig_mr;	/* signature MR */

	char *send_buf;
	char *recv_buf;
	uint8_t *data_buf;
	size_t data_buf_size;
	uint8_t *pi_buf;
	size_t pi_buf_size;
	int sock; /* TCP socket file descriptor */
};

struct signature_ops {
	const char *	name;
	size_t		pi_size;
	void		(*set_sig_domain)(struct ibv_exp_sig_domain *);
	void		(*dump_pi)(void *pi);
};

enum signature_types {
	SIG_TYPE_CRC32 = 0,
	SIG_TYPE_T10DIFF,

	SIG_TYPE_MAX,
};

void set_sig_domain_crc32(struct ibv_exp_sig_domain *sd);
void dump_pi_crc32(void *);
void set_sig_domain_t10dif(struct ibv_exp_sig_domain *sd);
void dump_pi_t10dif(void *);

const struct signature_ops sig_ops[SIG_TYPE_MAX] = {
	[SIG_TYPE_CRC32] = {
		.name		= "crc32",
		.pi_size	= 4,
		.set_sig_domain	= set_sig_domain_crc32,
		.dump_pi	= dump_pi_crc32,
	},
	[SIG_TYPE_T10DIFF] = {
		.name		= "t10dif",
		.pi_size	= 8,
		.set_sig_domain	= set_sig_domain_t10dif,
		.dump_pi	= dump_pi_t10dif,
	},
};

struct config_t config = {
	.dev_name	= NULL,
	.server_name	= NULL,
	.tcp_port	= 19875,
	.ib_port	= 1,
	.gid_idx	= -1,
	.block_size	= 512,
	.nb		= 8,
	.interleave	= 0,
	.sig		= &sig_ops[SIG_TYPE_CRC32],
	.pipeline	= 0,
	.corrupt_data	= 0,
};

static inline int is_server()
{
	return config.server_name == NULL;
}

const struct signature_ops *parse_sig_type(const char *type)
{
	const struct signature_ops *sig = NULL;
	int i;

	for (i = 0; i < SIG_TYPE_MAX; i++) {
		if (!strcmp(type, sig_ops[i].name)) {
			sig = &sig_ops[i];
			break;
		}
	}

	return sig;
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
				/* Server mode. Set up listening socket an accept a connection */
				listenfd = sockfd;
				sockfd = -1;

				setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
					   &enable_reuseaddr, sizeof(enable_reuseaddr));

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
	struct ibv_exp_wc *wc = &res->wc;
	int poll_result;
	int rc = 0;
	struct ibv_async_event event;

	/* poll the completion for a while before giving up of doing it .. */
	gettimeofday(&cur_time, NULL);
	start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	do {
		poll_result = ibv_exp_poll_cq(res->cq, 1, wc, sizeof(*wc));
		gettimeofday(&cur_time, NULL);
		cur_time_msec =
			(cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);

		if (!ibv_get_async_event(res->ib_ctx, &event))
			ibv_ack_async_event(&event);
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
		fprintf(stdout, "completion was found in CQ with status 0x%x, opcode %u\n",
			wc->status, wc->exp_opcode);
		/* check the completion status (here we don't care about the completion
     * opcode */
		if (wc->status != IBV_WC_SUCCESS) {
			fprintf(stderr,
				"got bad completion with status: 0x%x, vendor syndrome: 0x%x\n",
				wc->status, wc->vendor_err);
			rc = 1;
		}
	}
	return rc;
}

/******************************************************************************
 * Function: post_send
 *
 * Input
 * res pointer to resources structure
 * opcode IBV_WR_SEND, IBV_WR_RDMA_READ or IBV_WR_RDMA_WRITE
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, error code on failure
 *
 * Description
 * This function will create and post a send work request
 ******************************************************************************/
static int post_send(struct resources *res, int opcode, const struct msg_t *req)
{
	struct ibv_send_wr sr;
	struct ibv_sge sge;
	struct ibv_send_wr *bad_wr = NULL;
	int rc;
	/* prepare the scatter/gather entry */
	memset(&sge, 0, sizeof(sge));
	if (!req) {
		sge.addr = (uintptr_t)res->send_mr->addr;
		sge.length = MSG_SIZE;
		sge.lkey = res->send_mr->lkey;
	} else {
		sge.addr = (uintptr_t)res->sig_mr->addr;
		/* length is calculated according to wire domain */
		sge.length = (config.block_size + config.sig->pi_size) * config.nb;
		sge.lkey = res->sig_mr->lkey;
	}

	/* prepare the send work request */
	memset(&sr, 0, sizeof(sr));
	sr.next = NULL;
	sr.sg_list = &sge;
	sr.num_sge = 1;
	sr.opcode = opcode;
	sr.send_flags = IBV_SEND_SIGNALED;
	if (req) {
		sr.wr.rdma.remote_addr = ntohll(req->data.req.addr);
		sr.wr.rdma.rkey = ntohl(req->data.req.rkey);
	}
	/* there is a Receive Request in the responder side, so we won't get any into
   * RNR flow */
	rc = ibv_post_send(res->qp, &sr, &bad_wr);
	if (rc)
		fprintf(stderr, "failed to post SR\n");
	else {
		switch (opcode) {
		case IBV_WR_SEND:
			fprintf(stdout, "Send Request was posted\n");
			break;
		case IBV_WR_RDMA_READ:
			fprintf(stdout, "RDMA Read Request was posted\n");
			break;
		case IBV_WR_RDMA_WRITE:
			fprintf(stdout, "RDMA Write Request was posted\n");
			break;
		default:
			fprintf(stdout, "Unknown Request was posted\n");
			break;
		}
	}
	return rc;
}

static int post_send_pipeline(struct resources *res, const struct msg_t *req)
{
	struct ibv_exp_send_wr rdma_wr = {};
	struct ibv_exp_send_wr send_wr = {};
	struct ibv_sge rdma_sge;
	struct ibv_sge send_sge;
	struct ibv_exp_send_wr *bad_wr = NULL;
	struct msg_t *msg;
	int rc;

	if (config.corrupt_data) {
		res->data_buf[0] = 'e';
		res->data_buf[1] = 'r';
		res->data_buf[2] = 'r';
		res->data_buf[3] = 'o';
		res->data_buf[3] = 'r';
	}

	rdma_sge.addr = (uintptr_t)res->sig_mr->addr;
	/* length is calculated according to wire domain */
	rdma_sge.length = (config.block_size + config.sig->pi_size) * config.nb;
	rdma_sge.lkey = res->sig_mr->lkey;

	rdma_wr.next = &send_wr;
	rdma_wr.sg_list = &rdma_sge;
	rdma_wr.num_sge = 1;
	rdma_wr.exp_opcode = IBV_EXP_WR_RDMA_WRITE;
	rdma_wr.wr.rdma.remote_addr = ntohll(req->data.req.addr);
	rdma_wr.wr.rdma.rkey = ntohl(req->data.req.rkey);

	msg = (struct msg_t *)res->send_buf;
	memset(msg, 0, sizeof(*msg));
	msg->type = MSG_TYPE_READ_REP;
	msg->data.rep.status = htonl(MSG_REP_STATUS_OK);

	send_sge.addr = (uintptr_t)res->send_mr->addr;
	send_sge.length = MSG_SIZE;
	send_sge.lkey = res->send_mr->lkey;

	send_wr.next = NULL;
	send_wr.sg_list = &send_sge;
	send_wr.num_sge = 1;
	send_wr.exp_opcode = IBV_EXP_WR_SEND;
	send_wr.exp_send_flags = IBV_EXP_SEND_SIGNALED;
	send_wr.exp_send_flags |= IBV_EXP_SEND_SIG_PIPELINED;

	rc = ibv_exp_post_send(res->qp, &rdma_wr, &bad_wr);
	if (rc)
		fprintf(stderr, "failed to post pipelined WRs\n");
	else
		fprintf(stdout, "Post pipelined WRs\n");

	return rc;
}

/******************************************************************************
 * Function: post_receive
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
 *
 ******************************************************************************/
static int post_receive(struct resources *res)
{
	struct ibv_recv_wr rr;
	struct ibv_sge sge;
	struct ibv_recv_wr *bad_wr;
	int rc;

	/* prepare the scatter/gather entry */
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)res->recv_mr->addr;
	sge.length = MSG_SIZE;
	sge.lkey = res->recv_mr->lkey;

	/* prepare the receive work request */
	memset(&rr, 0, sizeof(rr));
	rr.sg_list = &sge;
	rr.num_sge = 1;

	rc = ibv_post_recv(res->qp, &rr, &bad_wr);
	if (rc)
		fprintf(stderr, "failed to post RR\n");
	else
		fprintf(stdout, "Receive Request was posted\n");
	return rc;
}

void set_sig_domain_none(struct ibv_exp_sig_domain *sd)
{
	memset(sd, 0, sizeof(struct ibv_exp_sig_domain));

	sd->sig_type = IBV_EXP_SIG_TYPE_NONE;
}

void set_sig_domain_crc32(struct ibv_exp_sig_domain *sd)
{
	memset(sd, 0, sizeof(struct ibv_exp_sig_domain));

	sd->sig_type = IBV_EXP_SIG_TYPE_CRC32;
	sd->sig.crc.pi_interval = config.block_size;
	sd->sig.crc.bg = 0xffffffff;
}

void dump_pi_crc32(void *pi)
{
	uint32_t crc = ntohl(*(uint32_t *)pi);

	fprintf(stdout, "crc32 0x%lx\n", crc);
}

struct t10dif_pi {
	uint16_t guard;
	uint16_t app_tag;
	uint32_t ref_tag;

} __attribute__((packed));

void dump_pi_t10dif(void *pi_ptr)
{
	struct t10dif_pi *pi = pi_ptr;

	uint32_t crc = ntohl(*(uint32_t *)pi);

	fprintf(stdout, "t10dif { guard 0x%x, application tag 0x%x, reference tag 0x%lx }\n",
		ntohs(pi->guard),
		ntohs(pi->app_tag),
		ntohl(pi->ref_tag));
}

void set_sig_domain_t10dif(struct ibv_exp_sig_domain *sd)
{
	memset(sd, 0, sizeof(struct ibv_exp_sig_domain));

	sd->sig_type = IBV_EXP_SIG_TYPE_T10_DIF;
	sd->sig.dif.bg_type = IBV_EXP_T10DIF_CRC;
	sd->sig.dif.pi_interval = config.block_size;
	sd->sig.dif.bg = 0x1234;
	sd->sig.dif.app_tag = 0x5678;
	sd->sig.dif.ref_tag = 0xabcdef90;
	sd->sig.dif.ref_remap = 1;
	sd->sig.dif.app_escape = 1;
	sd->sig.dif.ref_escape = 1;
	sd->sig.dif.apptag_check_mask = 0xffff;
}


int reg_sig_mr(struct resources *res,
	       enum sig_mode mode)
{
	struct ibv_exp_sig_attrs sig_attrs = {
		.check_mask = 0xff,
	};
	struct ibv_sge data;
	struct ibv_sge prot;
	struct ibv_exp_send_wr wr;
	struct ibv_exp_send_wr *bad_wr;
	int rc;

	switch (mode) {
	case SIG_MODE_INSERT:
	case SIG_MODE_STRIP:
		set_sig_domain_none(&sig_attrs.mem);
		config.sig->set_sig_domain(&sig_attrs.wire);
		break;
	case SIG_MODE_CHECK:
		config.sig->set_sig_domain(&sig_attrs.mem);
		config.sig->set_sig_domain(&sig_attrs.wire);
		break;
	default:
		break;
	}

	memset(&wr, 0, sizeof(wr));
	wr.exp_opcode = IBV_EXP_WR_REG_SIG_MR;
	wr.exp_send_flags = IBV_EXP_SEND_SIGNALED;
	wr.ext_op.sig_handover.sig_attrs = &sig_attrs;
	wr.ext_op.sig_handover.sig_mr = res->sig_mr;
	wr.ext_op.sig_handover.access_flags = IBV_ACCESS_LOCAL_WRITE |
	                                      IBV_ACCESS_REMOTE_READ |
	                                      IBV_ACCESS_REMOTE_WRITE;
	data.addr = (uintptr_t)res->data_mr->addr;
	data.lkey = res->data_mr->lkey;
	if ((mode == SIG_MODE_INSERT) ||
	    (mode == SIG_MODE_STRIP) ||
	    (!config.interleave))
		data.length = config.block_size * config.nb;
	else
		data.length = res->data_mr->length;
	wr.num_sge = 1;
	wr.sg_list = &data;

	if ((!res->pi_buf) ||
	    (mode == SIG_MODE_INSERT) ||
	    (mode == SIG_MODE_STRIP)) {
		wr.ext_op.sig_handover.prot = NULL;
	} else {
		prot.addr = (uint64_t)res->pi_mr->addr;
		prot.length = res->pi_mr->length;
		prot.lkey = res->pi_mr->lkey;
		wr.ext_op.sig_handover.prot = &prot;
	}

	rc = ibv_exp_post_send(res->qp, &wr, &bad_wr);
	if (rc) {
		fprintf(stderr, "post sig mr registration failed\n");
		return rc;
	}

	rc = poll_completion(res);
	if (rc) {
		fprintf(stderr, "poll completion failed\n");
	}

	fprintf(stdout, "Signature MR was registered with addr=%p, lkey=0x%x, rkey=0x%x\n",
		res->sig_mr->addr, res->sig_mr->lkey, res->sig_mr->rkey);

	return rc;
}


int inv_sig_mr(struct resources *res)
{
	struct ibv_exp_send_wr wr;
	struct ibv_exp_send_wr *bad_wr;
	int rc;

	memset(&wr, 0, sizeof(wr));
	wr.exp_opcode = IBV_EXP_WR_LOCAL_INV;
	wr.exp_send_flags = IBV_EXP_SEND_SIGNALED;
	wr.ex.invalidate_rkey = res->sig_mr->rkey;

	rc = ibv_exp_post_send(res->qp, &wr, &bad_wr);
	if (rc) {
		fprintf(stderr, "post sig mr ivalidate failed\n");
		return rc;
	}

	rc = poll_completion(res);
	if (rc) {
		fprintf(stderr, "poll completion failed\n");
	}
	fprintf(stdout, "Invalidate signature MR rkey=0x%x\n",
		res->sig_mr->rkey);

	return rc;
}

/******************************************************************************
 * Function: resources_init
 *
 * Input
 * res pointer to resources structure
 *
 * Output
 * res is initialized
 *
 * Returns
 * none
 *
 * Description
 * res is initialized to default values
 ******************************************************************************/
static void resources_init(struct resources *res)
{
	memset(res, 0, sizeof *res);
	res->sock = -1;

	res->data_buf_size = config.block_size * config.nb;

	if (config.interleave)
		res->data_buf_size += config.sig->pi_size * config.nb;
	else
		res->pi_buf_size = config.sig->pi_size * config.nb;
}

int alloc_and_register_buffer(struct ibv_pd *pd,
			      size_t size,
			      void **buf,
			      struct ibv_mr **mr)
{
	int mr_flags = 0;

	if (!size)
		return 0;

	*buf = malloc(size);
	if (!*buf) {
		fprintf(stderr, "failed to malloc %Zu bytes to memory buffer\n",
			size);
		return 1;
	}
	memset(*buf, 1, size);

	mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
		   IBV_ACCESS_REMOTE_WRITE;
	*mr = ibv_reg_mr(pd, *buf, size, mr_flags);
	if (!*mr) {
		fprintf(stderr, "ibv_reg_mr failed with mr_flags=0x%x\n",
			mr_flags);
		free(*buf);
		*buf = NULL;
		return 1;
	}

	return 0;
}

int set_nonblock_async_event_fd(struct ibv_context *ctx)
{
	int flags;
	int rc;

	flags = fcntl(ctx->async_fd, F_GETFL);
	rc = fcntl(ctx->async_fd, F_SETFL, flags | O_NONBLOCK);

	if (rc)
		fprintf(stderr, "failed to change file  descriptor of async event queue\n");

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
	struct ibv_exp_qp_init_attr qp_init_attr;
	struct ibv_device *ib_dev = NULL;
	struct ibv_exp_create_mr_in sig_mr_in = { };

	size_t size;
	int i;
	int cq_size = 0;
	int num_devices;
	int rc = 0;

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

	if (set_nonblock_async_event_fd(res->ib_ctx)) {
		rc = 1;
		goto resources_create_exit;
	}
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

	rc = alloc_and_register_buffer(res->pd, MSG_SIZE,
					(void **)&res->send_buf, &res->send_mr);
	if (rc) {
		goto resources_create_exit;
	}
	rc = alloc_and_register_buffer(res->pd, MSG_SIZE,
					(void **)&res->recv_buf, &res->recv_mr);
	if (rc) {
		goto resources_create_exit;
	}

	rc = alloc_and_register_buffer(res->pd, res->data_buf_size,
					(void **)&res->data_buf, &res->data_mr);
	if (rc) {
		goto resources_create_exit;
	}

	rc = alloc_and_register_buffer(res->pd, res->pi_buf_size,
					(void **)&res->pi_buf, &res->pi_mr);
	if (rc) {
		goto resources_create_exit;
	}

	sig_mr_in.pd = res->pd;
	sig_mr_in.attr.max_klm_list_size = 1;
	sig_mr_in.attr.create_flags = IBV_EXP_MR_SIGNATURE_EN;
	sig_mr_in.attr.exp_access_flags = IBV_ACCESS_LOCAL_WRITE |
					  IBV_ACCESS_REMOTE_READ |
					  IBV_ACCESS_REMOTE_WRITE;
	res->sig_mr = ibv_exp_create_mr(&sig_mr_in);
	if (!res->sig_mr) {
		fprintf(stdout, "failed to create the signature\n");
		goto resources_create_exit;
	}

	/* create the Queue Pair */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 0;
	qp_init_attr.send_cq = res->cq;
	qp_init_attr.recv_cq = res->cq;
	qp_init_attr.cap.max_send_wr = 2;
	qp_init_attr.cap.max_recv_wr = 1;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;

	/* signature specific attributes */
	qp_init_attr.pd = res->pd;
	qp_init_attr.comp_mask = IBV_QP_INIT_ATTR_PD;
	qp_init_attr.comp_mask |= IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS;
	qp_init_attr.exp_create_flags |= IBV_EXP_QP_CREATE_SIGNATURE_EN;
	if (is_server() && config.pipeline)
		qp_init_attr.exp_create_flags |= IBV_EXP_QP_CREATE_SIGNATURE_PIPELINE;

	res->qp = ibv_exp_create_qp(res->ib_ctx, &qp_init_attr);
	if (!res->qp) {
		fprintf(stderr, "failed to create QP\n");
		rc = 1;
		goto resources_create_exit;
	}
	fprintf(stdout, "QP was created, QP number=0x%x\n", res->qp->qp_num);
resources_create_exit:
	if (rc) {
		/* Error encountered, cleanup */
		if (res->qp) {
			ibv_destroy_qp(res->qp);
			res->qp = NULL;
		}
		if (res->sig_mr) {
			ibv_dereg_mr(res->sig_mr);
			res->sig_mr = NULL;
		}
		if (res->pi_mr) {
			ibv_dereg_mr(res->pi_mr);
			res->pi_mr = NULL;
		}
		if (res->data_mr) {
			ibv_dereg_mr(res->data_mr);
			res->data_mr = NULL;
		}
		if (res->send_mr) {
			ibv_dereg_mr(res->send_mr);
			res->send_mr = NULL;
		}
		if (res->recv_mr) {
			ibv_dereg_mr(res->recv_mr);
			res->recv_mr = NULL;
		}
		if (res->pi_buf) {
			free(res->pi_buf);
			res->pi_buf = NULL;
		}
		if (res->data_buf) {
			free(res->data_buf);
			res->data_buf = NULL;
		}
		if (res->send_buf) {
			free(res->send_buf);
			res->send_buf = NULL;
		}
		if (res->recv_buf) {
			free(res->recv_buf);
			res->recv_buf = NULL;
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
static int modify_qp_to_rts(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x12;
	attr.retry_cnt = 6;
	attr.rnr_retry = 0;
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

	if (config.gid_idx >= 0) {
		rc = ibv_query_gid(res->ib_ctx, config.ib_port, config.gid_idx,
				   &my_gid);
		if (rc) {
			fprintf(stderr,
				"could not get gid for port %d, index %d\n",
				config.ib_port, config.gid_idx);
			return rc;
		}
	} else
		memset(&my_gid, 0, sizeof my_gid);
	local_con_data.qp_num = htonl(res->qp->qp_num);
	local_con_data.lid = htons(res->port_attr.lid);
	memcpy(local_con_data.gid, &my_gid, 16);
	fprintf(stdout, "\nLocal LID = 0x%x\n", res->port_attr.lid);

	if (sock_sync_data(res->sock, sizeof(struct cm_con_data_t),
			   (char *)&local_con_data,
			   (char *)&tmp_con_data) < 0) {
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
	fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
	fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
	if (config.gid_idx >= 0) {
		uint8_t *p = remote_con_data.gid;
		fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],p[10], p[11], p[12], p[13], p[14], p[15]);
	}

	/* modify the QP to init */
	rc = modify_qp_to_init(res->qp);
	if (rc) {
		fprintf(stderr, "change QP state to INIT failed\n");
		goto connect_qp_exit;
	}

	rc = post_receive(res);
	if (rc) {
		fprintf(stderr, "failed to post RR\n");
		goto connect_qp_exit;
	}
	/* modify the QP to RTR */
	rc = modify_qp_to_rtr(res->qp, remote_con_data.qp_num,
			      remote_con_data.lid, remote_con_data.gid);
	if (rc) {
		fprintf(stderr, "failed to modify QP state to RTR\n");
		goto connect_qp_exit;
	}
	rc = modify_qp_to_rts(res->qp);
	if (rc) {
		fprintf(stderr, "failed to modify QP state to RTR\n");
		goto connect_qp_exit;
	}
	fprintf(stdout, "QP state was change to RTS\n");
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
	if (res->qp)
		if (ibv_destroy_qp(res->qp)) {
			fprintf(stderr, "failed to destroy QP\n");
			rc = 1;
		}
	if (res->sig_mr)
		if (ibv_dereg_mr(res->sig_mr)) {
			fprintf(stderr, "failed to deregister mr\n");
			rc = 1;
		}
	if (res->pi_mr)
		if (ibv_dereg_mr(res->pi_mr)) {
			fprintf(stderr, "failed to deregister mr\n");
			rc = 1;
		}
	if (res->data_mr)
		if (ibv_dereg_mr(res->data_mr)) {
			fprintf(stderr, "failed to deregister mr\n");
			rc = 1;
		}
	if (res->send_mr)
		if (ibv_dereg_mr(res->send_mr)) {
			fprintf(stderr, "failed to deregister mr\n");
			rc = 1;
		}
	if (res->recv_mr)
		if (ibv_dereg_mr(res->recv_mr)) {
			fprintf(stderr, "failed to deregister mr\n");
			rc = 1;
		}
	if (res->pi_buf)
		free(res->pi_buf);
	if (res->data_buf)
		free(res->data_buf);
	if (res->send_buf)
		free(res->send_buf);
	if (res->recv_buf)
		free(res->recv_buf);
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

int check_sig_mr(struct ibv_mr *mr)
{
	struct ibv_exp_mr_status status;
	int rc;

	rc = ibv_exp_check_mr_status(mr, IBV_EXP_MR_CHECK_SIG_STATUS, &status);
	if (rc) {
		fprintf(stderr, "check mr status failed\n");
		return rc;
	}

	rc = status.fail_status;
	fprintf(stdout, "mr status: %s\n",
		(rc ? "SIG ERROR" : "OK"));

	return rc;
}

int send_repl(struct resources *res, uint8_t type, uint32_t status)
{
	struct msg_t *msg;
	int rc;

	msg = (struct msg_t *)res->send_buf;
	memset(msg, 0, sizeof(*msg));
	msg->type = type;
	msg->data.rep.status = htonl(status);

	rc = post_send(res, IBV_WR_SEND, NULL);
	if (rc)
		return rc;

	rc = poll_completion(res);
	if (rc)
		return rc;

	return rc;
}


int handle_write_req(struct resources *res,
		     const struct msg_t *req)
{
	int rc = 0;

	rc = reg_sig_mr(res, SIG_MODE_CHECK);
	if (rc)
		goto err_exit;

	rc = post_send(res, IBV_WR_RDMA_READ, req);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

	rc = check_sig_mr(res->sig_mr);
	if (rc)
		goto err_exit;

	rc = inv_sig_mr(res);
	if (rc)
		goto err_exit;

	rc = post_receive(res);
	if (rc)
		goto err_exit;

	rc = send_repl(res, MSG_TYPE_WRITE_REP, MSG_REP_STATUS_OK);
err_exit:
	return rc;
}

int handle_read_req(struct resources *res,
		    const struct msg_t *req)
{
	int rc = 0;

	rc = reg_sig_mr(res, SIG_MODE_CHECK);
	if (rc)
		goto err_exit;

	rc = post_send(res, IBV_WR_RDMA_WRITE, req);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

	rc = check_sig_mr(res->sig_mr);
	if (rc)
		goto err_exit;

	rc = inv_sig_mr(res);
	if (rc)
		goto err_exit;

	rc = post_receive(res);
	if (rc)
		goto err_exit;

	rc = send_repl(res, MSG_TYPE_READ_REP, MSG_REP_STATUS_OK);
err_exit:
	return rc;
}

int handle_read_req_pipeline(struct resources *res,
			     const struct msg_t *req)
{
	struct ibv_exp_wc *wc = &res->wc;
	int rc = 0;

	rc = post_receive(res);
	if (rc)
		goto err_exit;

	rc = reg_sig_mr(res, SIG_MODE_CHECK);
	if (rc)
		goto err_exit;

	rc = post_send_pipeline(res, req);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

	if (wc->exp_wc_flags & IBV_EXP_WC_SIG_PIPELINE_CANCELED) {
		fprintf(stderr, "A signature error has been detected\n");

		rc = send_repl(res, MSG_TYPE_READ_REP,
			       MSG_REP_STATUS_FAIL);
		if (rc)
			goto err_exit;
	}

	rc = check_sig_mr(res->sig_mr);
	if (rc && !config.corrupt_data)
		goto err_exit;

	rc = inv_sig_mr(res);

err_exit:
	return rc;
}

int server(struct resources *res)
{
	int rc = 0;
	int close_conn = 0;
	struct msg_t *msg = (struct msg_t *)res->recv_buf;

	while (!close_conn) {
		rc = poll_completion(res);
		if (rc)
			break;

		switch (msg->type) {
		case MSG_TYPE_WRITE_REQ:
			rc = handle_write_req(res, msg);
			if (rc)
				close_conn = 1;
			break;

		case MSG_TYPE_READ_REQ:
			if (config.pipeline)
				rc = handle_read_req_pipeline(res, msg);
			else
				rc = handle_read_req(res, msg);
			if (rc)
				close_conn = 1;
			break;

		case MSG_TYPE_CLOSE_CONN:
			close_conn = 1;
			break;

		default:
			fprintf(stderr, "An invalid message was received: type 0x%x\n",
				msg->type);
			rc = 1;
			close_conn = 1;
		}

	}

err_exit:
	return rc;
}


int client(struct resources *res)
{
	int rc = 0;
	struct msg_t *msg;
	int i;

	/* ============ WRITE OPERATION ==========================  */
	rc = reg_sig_mr(res, SIG_MODE_INSERT);
	if (rc)
		goto err_exit;

	msg = (struct msg_t *)res->send_buf;
	msg->type = MSG_TYPE_WRITE_REQ;
	msg->data.req.addr = htonll((uintptr_t)res->sig_mr->addr);
	msg->data.req.rkey = htonl(res->sig_mr->rkey);

	fprintf(stdout, "Send write request\n");

	rc = post_send(res, IBV_WR_SEND, NULL);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

	msg = (struct msg_t *)res->recv_buf;
	if (msg->type != MSG_TYPE_WRITE_REP) {
		fprintf(stderr,
			"An invalid reply message was received, type 0x%x",
			msg->type);
		goto err_exit;
	}

        fprintf(stdout, "WRITE_REPLY: status %s\n",
                (ntohl(msg->data.rep.status) == MSG_REP_STATUS_OK) ? "OK"
                                                                   : "FAIL");

	rc = check_sig_mr(res->sig_mr);
	if (rc)
		goto err_exit;

	rc = inv_sig_mr(res);
	if (rc)
		goto err_exit;

	/* ============ READ OPERATION ==========================  */

	rc = post_receive(res);
	if (rc)
		goto err_exit;

	rc = reg_sig_mr(res, SIG_MODE_CHECK);
	if (rc)
		goto err_exit;

	msg = (struct msg_t *)res->send_buf;
	msg->type = MSG_TYPE_READ_REQ;
	msg->data.req.addr = htonll((uintptr_t)res->sig_mr->addr);
	msg->data.req.rkey = htonl(res->sig_mr->rkey);

	rc = post_send(res, IBV_WR_SEND, NULL);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

	msg = (struct msg_t *)res->recv_buf;
	if (msg->type != MSG_TYPE_READ_REP) {
		fprintf(stderr,
			"An invalid reply message was received, type 0x%x",
			msg->type);
		goto err_exit;
	}

        fprintf(stdout, "READ_REPLY: status %s\n",
                (ntohl(msg->data.rep.status) == MSG_REP_STATUS_OK) ? "OK"
                                                                   : "FAIL");

	rc = check_sig_mr(res->sig_mr);

	fprintf(stdout, "Dump PI:\n");
	for (i = 0; i < config.nb; i++) {
		uint8_t *pi;
		if (config.interleave)
			pi = res->data_buf + (config.block_size * (i + 1)) +
				config.sig->pi_size * i;
		else
			pi =  res->pi_buf + config.sig->pi_size * i;

		fprintf(stdout, "block[%d] : ", i);
		config.sig->dump_pi(pi);
	}

	rc = inv_sig_mr(res);
	if (rc)
		goto err_exit;

	/* ============== Send close connection ===================== */

	msg = (struct msg_t *)res->send_buf;
	msg->type = MSG_TYPE_CLOSE_CONN;
	rc = post_send(res, IBV_WR_SEND, NULL);
	if (rc)
		goto err_exit;

	rc = poll_completion(res);
	if (rc)
		goto err_exit;

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

	fprintf(stdout, " Block size : %u\n", config.block_size);
	fprintf(stdout, " Number of blocks : %u\n", config.nb);
	fprintf(stdout, " Interleave : %u\n", config.interleave);
	fprintf(stdout, " Signature type : %s\n", config.sig->name);
	fprintf(stdout, " Pipeline : %d\n", config.pipeline);
	fprintf(stdout, " Corrupt data : %d\n", config.corrupt_data);
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
	fprintf(stdout, " %s start a server and wait for connection\n", argv0);
	fprintf(stdout, " %s <host> connect to server at <host>\n", argv0);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout,
		" -h, --help                   print this message\n");
	fprintf(stdout,
		" -p, --port <port>            listen on/connect to port <port> (default 18515)\n");
	fprintf(stdout,
		" -d, --ib-dev <dev>           use IB device <dev> (default first device found)\n");
	fprintf(stdout,
		" -i, --ib-port <port>         use port <port> of IB device (default 1)\n");
	fprintf(stdout,
		" -g, --gid-idx <gid index>    gid index to be used in GRH "
		"(default not used)\n");
	fprintf(stdout,
		" -b, --block-size <size>      size of data block, only 512 and 4096 are supported (default 512)\n");
	fprintf(stdout,
		" -n, --number-of-blocks <NB>  Number of blocks per RDMA operation (default 8)\n");
	fprintf(stdout,
		" -o, --interleave             Data blocks and protection blocks are interleaved in the same buf\n");
	fprintf(stdout,
		" -s, --sig-type <type>        Supported signature types: crc32, t10dif (default crc32)\n");
	fprintf(stdout,
		" -l, --pipeline               Enable pipeline\n");
	fprintf(stdout,
		" -c, --corrupt-data           Corrupt data for READ read operation\n");
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
	char temp_char;

	/* parse the command line parameters */
	while (1) {
		int c;
		static struct option long_options[] = {
			{ .name = "help",		.has_arg = 0, .val = 'h' },
			{ .name = "port",		.has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",		.has_arg = 1, .val = 'd' },
			{ .name = "ib-port",		.has_arg = 1, .val = 'i' },
			{ .name = "gid-idx",		.has_arg = 1, .val = 'g' },
			{ .name = "block-size",		.has_arg = 1, .val = 'b' },
			{ .name = "number-of-blocks",	.has_arg = 1, .val = 'n' },
			{ .name = "interleave",		.has_arg = 0, .val = 'o' },
			{ .name = "sig-type",		.has_arg = 1, .val = 's' },
			{ .name = "pipeline",		.has_arg = 0, .val = 'l' },
			{ .name = "corrupt-data",	.has_arg = 0, .val = 'c' },
			{ .name = NULL,			.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "hp:d:i:g:b:n:os:lc", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
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
		case 'b':
			config.block_size = strtoul(optarg, NULL, 0);
			if (config.block_size != 512 && config.block_size != 4096) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'n':
			config.nb = strtoul(optarg, NULL, 0);
			if (config.nb < 1) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'o':
			config.interleave = 1;
			break;
		case 's':
			config.sig = parse_sig_type(optarg);
			if (!config.sig) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'l':
			config.pipeline = 1;
			break;
		case 'c':
			config.corrupt_data = 1;
			break;
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

	resources_init(&res);

	if (resources_create(&res)) {
		fprintf(stderr, "failed to create resources\n");
		goto main_exit;
	}

	if (connect_qp(&res)) {
		fprintf(stderr, "failed to connect QPs\n");

		goto main_exit;
	}

	if (is_server())
		rc = server(&res);
	else
		rc = client(&res);

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
