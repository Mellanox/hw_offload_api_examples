/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#include <rdma/rdma_cma.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
		if (log_lvl >= 2)					\
			fprintf(stdout, "DEBUG: " format, ##arg);	\
	} while (0)

#define info(format, arg...)						\
	do {								\
		if (log_lvl >= 1)					\
			fprintf(stdout, format, ##arg);			\
	} while (0)

#define err(format, arg...)						\
	do {								\
		if (log_lvl >= 0)					\
			fprintf(stderr, "ERROR: " format, ##arg);	\
	} while (0)

/* structure of test parameters */
struct config {
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	unsigned long int port;
	int nb;
	int queue_depth;
	int time;		/* test time in seconds */
	long int iters;		/* number of iteratios */
} conf = {
	.port		= 19875,
	.nb		= 8,
	.queue_depth 	= 8,
	.time 		= 1,
	.iters		= -1,
};

#define PI_SIZE 8

#define MAX_SEND_WRS 5
#define CQ_SIZE ((MAX_SEND_WRS + 2) * conf.queue_depth)

#define RDMA_SGL_SIZE 4

#define IOV_MAX_SIZE 1

#define SERVER_DATA_SIZE 512

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
	struct mlx5dv_mkey *sig_mkey;
};

/* structure of system resources */
struct resources {
	/* RDMA CM stufff */
	struct rdma_cm_id *cm_id;	/* connection on client side,*/
					/* listener on server side. */
	struct rdma_cm_id *child_cm_id;	/* connection on server side */
	struct ibv_context *ib_ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qp;

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

static inline bool is_client()
{
	return conf.dst_addr.ss_family;
}

static inline bool is_server()
{
	return !is_client();
}

static volatile bool stop = false;
static bool skip = false;

static void signal_handler(int sig)
{
	stop = true;
}

static int set_signal_handler()
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
	if (rc) {
		err("ibv_post_recv: wr_id %lu: %s\n", desc->wr.wr_id,
		    strerror(rc));
		return -1;
	}

	return 0;
}

static int post_recv_all(struct resources *res)
{
	uint64_t req_id;
	struct rx_desc *desc;

	for (req_id = 0; req_id < conf.queue_depth; req_id++) {
		desc = get_rx_desc(res, req_id);

		desc->wr.wr_id = req_id;
		if (post_recv(get_qp(res), desc))
			return -1;
	}

	return 0;
}

struct ibv_mr * alloc_mr(struct ibv_pd *pd, size_t size)
{
	int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
		       IBV_ACCESS_REMOTE_WRITE;
	void *ptr;
	struct ibv_mr *mr;

	ptr = calloc(1, size);
	if (!ptr) {
		err("calloc: %s\n", strerror(errno));
		return NULL;
	}

	mr = ibv_reg_mr(pd, ptr, size, mr_flags);
	if (!mr) {
		err("ibv_reg_mr: %s\n", strerror(errno));
		free(ptr);
		return NULL;
	}

	return mr;
}

static int free_mr(struct ibv_mr *mr)
{
	void *ptr;
	int rc;

	if (!mr)
		return 0;

	ptr = mr->addr;
	rc = ibv_dereg_mr(mr);
	if (rc)
		err("ibv_dereg_mr: %s\n", strerror(rc));

	free(ptr);

	return rc;
}

static void fill_data_buffer(uint8_t *data, size_t size)
{
	int i, block_num = size / (SERVER_DATA_SIZE + PI_SIZE);

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

static struct mlx5dv_mkey *create_sig_mkey(struct resources *res)
{
	struct mlx5dv_mkey_init_attr mkey_attr = {};
	mkey_attr.pd = res->pd;
	mkey_attr.max_entries = 1;
	mkey_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
				 MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE;
	struct mlx5dv_mkey *mkey;

	mkey = mlx5dv_create_mkey(&mkey_attr);
	if (!mkey) {
		if (errno != EOPNOTSUPP && errno != ENOTSUP) {
			err("mlx5dv_create_mkey: %s\n", strerror(errno));
		} else {
			info("mlx5dv_create_mkey: %s\n", strerror(errno));
			skip = true;
		}
	}

	return mkey;
}

static int destroy_sig_mkey(struct mlx5dv_mkey **mkey)
{
	int rc;

	if (!*mkey)
		return 0;

	rc = mlx5dv_destroy_mkey(*mkey);
	if (rc) {
		err("mlx5dv_destroy_mkey: %s\n", strerror(rc));
		return -1;
	}
	*mkey = NULL;

	return 0;
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
		return -1;

	res->recv_buf = res->recv_mr->addr;

	rx = calloc(num_rx_descs, sizeof(struct rx_desc));
	if (!rx) {
		err("calloc: %s\n", strerror(errno));
		rc = -1;
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

static int destroy_rx(struct resources *res)
{
	int rc;

	if (res->rx) {
		free(res->rx);
		res->rx = NULL;
		res->num_rx_descs = 0;
	}

	rc = free_mr(res->recv_mr);
	res->recv_mr = NULL;
	res->recv_buf = NULL;

	return rc;
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
		err("calloc: %s\n", strerror(errno));
		rc = -1;
		goto err_exit;
	}

	for (i = 0; i < num_tx_descs; i++, offset += max_msg_size) {
		struct tx_desc *desc = &tx[i];

		desc->sig_mkey = create_sig_mkey(res);
		if (!desc->sig_mkey) {
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

		destroy_sig_mkey(&desc->sig_mkey);
	}
	free(tx);
err_exit:
	res->tx = NULL;
	return rc;
}

static int destroy_tx(struct resources *res)
{
	int i;
	int rc = 0;

	if (res->tx) {
		for (i = 0; i < res->num_tx_descs; i++) {
			struct tx_desc *desc = &res->tx[i];

			if (destroy_sig_mkey(&desc->sig_mkey))
				rc = -1;
		}
		free(res->tx);
		res->tx = NULL;
		res->num_tx_descs = 0;
	}

	return rc;
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
		return -1;

	res->data_buf = res->data_mr->addr;
	res->data_buf_size = task_data_size * num_tasks;

	tasks = calloc(num_tasks, sizeof(struct task));
	if (!tasks) {
		err("calloc: %s\n", strerror(errno));
		rc = -1;
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
	}
	return 0;
err_free_buf:
	free_mr(res->data_mr);
	res->data_buf = NULL;
	res->data_mr = NULL;
	res->data_buf_size = 0;
	return rc;
}

static int destroy_tasks(struct resources *res)
{
	int rc;

	if (res->tasks) {
		free(res->tasks);
		res->tasks = NULL;
		res->num_tasks = 0;
	}
	rc = free_mr(res->data_mr);
	res->data_buf = NULL;
	res->data_mr = NULL;
	res->data_buf_size = 0;

	return rc;
}

static int dealloc_pd(struct resources *res)
{
	int rc;

	if (!res->pd)
		return 0;

	rc = ibv_dealloc_pd(res->pd);
	if (rc) {
		err("ibv_dealloc_pd: %s\n", strerror(rc));
		rc = -1;
	}
	res->pd = NULL;

	return rc;
}

static int destroy_cq(struct resources *res)
{
	int rc;

	if (!res->cq)
		return 0;

	rc = ibv_destroy_cq(res->cq);
	if (rc) {
		err("ibv_destroy_cq: %s\n", strerror(rc));
		rc = -1;
	}
	res->cq = NULL;

	return rc;
}

static int destroy_qp(struct resources *res)
{
	uint32_t qpn;
	int rc;

	if (!res->qp)
		return 0;

	qpn = res->qp->qp_num;

	rc = ibv_destroy_qp(res->qp);
	if (rc) {
		err("ibv_destroy_qp: QP 0x%x: %s\n", qpn,
		    strerror(rc));
		rc = -1;
	}
	res->qp = NULL;

	return rc;
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
	struct ibv_qp *qp;

	/* signature specific attributes */
	mlx5_qp_attr.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS;
	mlx5_qp_attr.send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE;
	if (is_server()) {
		mlx5_qp_attr.comp_mask |=
		    MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
		mlx5_qp_attr.create_flags = MLX5DV_QP_CREATE_SIG_PIPELINING;
	}

	qp = mlx5dv_create_qp(res->ib_ctx, &qp_init_attr, &mlx5_qp_attr);
	if (!qp) {
		if (errno != EOPNOTSUPP && errno != ENOTSUP) {
			err("mlx5dv_create_qp: %s\n", strerror(errno));
		} else {
			info("mlx5dv_create_qp: %s\n", strerror(errno));
			skip = true;
		}
	}

	return qp;
}

static int check_sig_mkey(struct task *task, struct mlx5dv_mkey *mkey)
{
	struct mlx5dv_mkey_err err_info;
	const char *sig_err_str = "";
	int sig_err;
	int rc;

	rc = mlx5dv_mkey_check(mkey, &err_info);
	if (rc) {
		err("mlx5dv_mkey_check: %s\n", strerror(rc));
		return -1;
	}

	sig_err = err_info.err_type;
	switch (sig_err) {
	case MLX5DV_MKEY_NO_ERR:
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_REFTAG:
		sig_err_str = "REF_TAG";
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_APPTAG:
		sig_err_str = "APP_TAG";
		break;
	case MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD:
		sig_err_str = "BLOCK_GUARD";
		break;
	default:
		err("unknown sig error %d\n", sig_err);
		return -1;
	}

	if (sig_err)
		dbg("REQ[%lu]: SIG ERROR: %s: expected %lu, actual %lu, offset %lu\n",
		    task->req_id, sig_err_str, err_info.err.sig.expected_value,
		    err_info.err.sig.actual_value, err_info.err.sig.offset);

	return sig_err;
}

static void set_sig_domain_t10dif_type3(struct mlx5dv_sig_block_domain *domain, void *sig)
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
		dbg("IBV_EVENT_SQ_DRAINED, QP 0x%x\n",
		    event->element.qp->qp_num);
		break;
	default:
		err("Unknown event (%d)\n", event->event_type);
	}
}

static void configure_sig_mkey(struct resources *res,
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

	mkey = desc->sig_mkey;

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

static int resources_destroy(struct resources *res)
{
	int rc = 0;

	if (destroy_qp(res))
		rc = -1;

	if (destroy_tasks(res))
		rc = -1;

	if (destroy_tx(res))
		rc = -1;

	if (destroy_rx(res))
		rc = -1;

	if (destroy_cq(res))
		rc = -1;

	if (dealloc_pd(res))
		rc = -1;

	res->ib_ctx = NULL;

	if (res->child_cm_id) {
		if (rdma_destroy_id(res->child_cm_id)) {
			err("rdma_destroy_id: %s\n", strerror(errno));
			rc = -1;
		}
		res->child_cm_id = NULL;
	}

	if (res->cm_id) {
		if (rdma_destroy_id(res->cm_id)) {
			err("rdma_destroy_id: %s\n", strerror(errno));
			rc = -1;
		}
		res->cm_id = NULL;
	}

	return rc;
}

static int set_nonblock_async_event_fd(struct ibv_context *ctx)
{
	int flags;

	flags = fcntl(ctx->async_fd, F_GETFL);

	if (fcntl(ctx->async_fd, F_SETFL, flags | O_NONBLOCK)) {
		err("set O_NONBLOCK for ibv_context->async_fd: %s\n",
		    strerror(errno));
		return -1;
	}

	return 0;
}

static int resources_create(struct resources *res)
{
	int rc;

	if (is_client())
		res->ib_ctx = res->cm_id->verbs;
	else
		res->ib_ctx = res->child_cm_id->verbs;

	if (!mlx5dv_is_supported(res->ib_ctx->device)) {
		info("device %s does not support MLX5DV APIs\n", ibv_get_device_name(res->ib_ctx->device));
		skip = true;
		goto err_exit;
	}

	if (set_nonblock_async_event_fd(res->ib_ctx))
		goto err_exit;

	/* allocate Protection Domain */
	res->pd = ibv_alloc_pd(res->ib_ctx);
	if (!res->pd) {
		err("ibv_alloc_pd: %s\n", strerror(errno));
		goto err_exit;
	}

	/* number of send WRs + one recv WR */
	res->cq = ibv_create_cq(res->ib_ctx, CQ_SIZE, NULL, NULL, 0);
	if (!res->cq) {
		err("ibv_create_cq: size %u: %s\n", CQ_SIZE, strerror(errno));
		goto err_exit;
	}

	rc = create_tx(res);
	if (rc)
		goto err_exit;

	rc = create_rx(res);
	if (rc)
		goto err_exit;

	rc = create_tasks(res);
	if (rc)
		goto err_exit;

	if (is_server())
		fill_data_buffer(res->data_buf, res->data_buf_size);

	res->qp = create_qp(res);
	if (!res->qp)
		goto err_exit;

	return 0;

err_exit:
	resources_destroy(res);
	return -1;
}

static int modify_qp_to_err(struct ibv_qp *qp)
{
	struct ibv_qp_attr qp_attr = {};

	qp_attr.qp_state = IBV_QPS_ERR;
	if (ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE)) {
		err("ibv_modify_qp: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int modify_qp_from_sqd_to_rts(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr = {};
	int flags = IBV_QP_STATE | IBV_QP_CUR_STATE;

	attr.qp_state = IBV_QPS_RTS;
	attr.cur_qp_state = IBV_QPS_SQD;

	if (ibv_modify_qp(qp, &attr, flags)) {
		err("ibv_modify_qp: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static void flush_qp(struct resources *res) {
	struct timespec sleep = { .tv_sec = 0, .tv_nsec = 1000000, };
	struct ibv_wc wc;

	if (modify_qp_to_err(res->qp))
		err("modify QP to ERR\n");
	/*
	 * Async events are out of scope of this example.
	 * However, you should use IBV_EVENT_QP_LAST_WQE_REACHED event
	 * instead of a sleep.
	 */
	nanosleep(&sleep, NULL);

	while (ibv_poll_cq(res->cq, 1, &wc)) {
	}
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
	const char *type_str;
	int rc;

	switch (type) {
	case MSG_TYPE_READ_REQ:
		type_str = "READ";
		break;
	case MSG_TYPE_STOP_REQ:
		type_str = "STOP";
		break;
	default:
		err("send req: req_id %lu: unknown type %d\n", req_id, type);
		return -1;
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
	qpx->wr_id = req_id;
	qpx->wr_flags = IBV_SEND_SIGNALED;

	ibv_wr_send(qpx);

	ibv_wr_set_inline_data(qpx, &msg, msg_length);

	rc = ibv_wr_complete(qpx);
	if (rc) {
		err("send req: req_id %lu, type %s: %s\n", req_id, type_str,
		    strerror(rc));
		    return -1;
	}

	return 0;
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

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &start_time)) {
		err("clock_gettime: %s", strerror(errno));
		rc = -1;
		goto err_exit;
	}

	while (!stop && conf.iters != 0) {
		int polled_comps;

		polled_comps = ibv_poll_cq(res->cq, MAX_WC_PER_POLL, wc);
		res->polls_counter++;
		if (!polled_comps)
			continue;
		if (polled_comps < 0) {
			err("ibv_poll_cq: %s\n", strerror(errno));
			rc = -1;
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
				break;
			case IBV_WC_RECV:
				desc = get_rx_desc(res, wc[i].wr_id);

				res->io_counter++;
                                conf.iters = (conf.iters > 0) ? conf.iters - 1
                                                              : conf.iters;

                                msg = desc->msg;
				hdr = (struct msg_rep_hdr *)msg;
				req_id = ntohll(hdr->id);
				status = ntohs(hdr->status);

				if (status == MSG_REP_STATUS_OK) {
				} else if (status == MSG_REP_STATUS_SIG_ERROR) {
					dbg("REP[%lu]: received with status SIG_ERROR\n", req_id);
				} else {
					err("REP[%lu]: received, status UNKNOWN\n", req_id);
					rc = -1;
					stop = true;
					break;
				}

				if (post_recv(get_qp(res), desc)) {
					rc = -1;
					stop = true;
					break;
				}

				if (client_send_req(res, req_id, MSG_TYPE_READ_REQ)) {
					rc = -1;
					stop = true;
				}
				break;
			default:
				err("unknown WC opcode %d\n", wc[i].opcode);
				rc = -1;
				stop = true;
			}
		}
	}

	req_id = conf.queue_depth;
	if (client_send_req(res, req_id, MSG_TYPE_STOP_REQ)) {
		rc = -1;
		goto err_exit;
	}
	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end_time)) {
		err("clock_gettime: %s\n", strerror(errno));
		rc = -1;
		goto err_exit;
	}
	iops = (end_time.tv_sec - start_time.tv_sec) * 1000;
	iops += (end_time.tv_nsec - start_time.tv_nsec) / 1000000;
	if (iops)
		iops = (res->io_counter * 1000) / iops;
	info("IOps : %lu\n", iops);

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

	lkey = desc->sig_mkey->lkey;
	addr = 0; // offset in sig_mkey
	// length of the data on wire domain
	length = conf.nb * SERVER_DATA_SIZE;

	ibv_wr_set_sge(qpx, lkey, addr, length);
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

	return ibv_wr_complete(qpx);
}

static inline int server_handle_async_event(struct resources *res)
{
	struct ibv_qp *qp;
	struct ibv_qp_ex *qpx;
	struct mlx5dv_qp_ex *dv_qp;
	struct task *task;
	struct tx_desc *desc;
	int i, canceled_wrs, rc;

	qp = res->qp;
	qpx = ibv_qp_to_qp_ex(qp);
	dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);

	for (i = 0; i < conf.queue_depth; i++) {
		task = get_task(res, i);
		if (task->status != TASK_STATUS_REPLY_SENT)
			/* Skip non-active tasks */
			continue;

		desc = get_tx_desc(res, i);
		rc = check_sig_mkey(task, desc->sig_mkey);
		if (rc < 0)
			return -1;

		/* Skip if no signature error is detected */
		if (!rc)
			continue;

		/* Cancel SEND WR with reply OK, if signature error was detected */
		canceled_wrs = mlx5dv_qp_cancel_posted_send_wrs(dv_qp, task->req_id);
		if (canceled_wrs < 0) {
			err("mlx5dv_qp_cancel_posted_send_wrs: %s\n",
			    strerror(-canceled_wrs));
			return -1;
		}

		/*
		 * We post one SEND WR with wr_id == task->req_id per task.
		 * And we expect one WR is canceled here.
		 */
		if (canceled_wrs != 1) {
			err("%d WRs were canceled, but 1 canceled WR is expected\n",
			    canceled_wrs);
			return -1;
		}

		dbg("REQ[%lu]: %d send wrs canceled\n", task->req_id, canceled_wrs);
		task->status = TASK_STATUS_WR_CANCELED_WITH_SIG_ERR;
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
		} else {
			dbg("REP[%lu]: canceled reply with status OK\n", task->req_id);
			dbg("REP[%lu]: send reply with status SIG_ERROR\n", task->req_id);
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

static int cm_bind_client(struct resources *res)
{
	struct rdma_cm_id *cm_id = res->cm_id;
	int rc;

	if (conf.dst_addr.ss_family == AF_INET)
		((struct sockaddr_in *)&conf.dst_addr)->sin_port = htobe16(conf.port);
	else
		((struct sockaddr_in6 *)&conf.dst_addr)->sin6_port = htobe16(conf.port);

	if (conf.src_addr.ss_family)
		rc = rdma_resolve_addr(cm_id, (struct sockaddr *)&conf.src_addr,
				       (struct sockaddr *)&conf.dst_addr, 2000);
	else
		rc = rdma_resolve_addr(cm_id, NULL, (struct sockaddr *)&conf.dst_addr, 2000);

	if (rc) {
		err("rdma_resolve_addr: %s\n", strerror(errno));
		return -1;
	}

	if (rdma_resolve_route(cm_id, 2000)) {
		err("rdma_resolve_route: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int cm_bind_server(struct resources *res)
{
	struct rdma_cm_id *cm_id = res->cm_id;

	/* Use IPv4 0.0.0.0:<port> by default */
	if (!conf.src_addr.ss_family)
		conf.src_addr.ss_family = AF_INET;

	if (conf.src_addr.ss_family == AF_INET)
		((struct sockaddr_in *)&conf.src_addr)->sin_port = htobe16(conf.port);
	else
		((struct sockaddr_in6 *)&conf.src_addr)->sin6_port = htobe16(conf.port);

	if (rdma_bind_addr(cm_id, (struct sockaddr *)&conf.src_addr)) {
		err("rdma_bind_addr: %s\n", strerror(errno));
		return -1;
	}

	if (rdma_listen(cm_id, 0)) {
		err("rdma_listen: %s\n", strerror(errno));
		return -1;
	}

	if (rdma_get_request(cm_id, &res->child_cm_id)) {
		err("rdma_get_request: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static inline int cm_bind(struct resources *res)
{
	if (is_client())
		return cm_bind_client(res);

	return cm_bind_server(res);
}

static int cm_modify_qp(struct resources *res, struct rdma_cm_id *cm_id,
			enum ibv_qp_state state)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask;

	qp_attr.qp_state = state;
	if (rdma_init_qp_attr(cm_id, &qp_attr, &qp_attr_mask)) {
		err("rdma_init_qp_attr: %s\n", strerror(errno));
		return -1;
	}

	if (ibv_modify_qp(res->qp, &qp_attr, qp_attr_mask)) {
		err("ibv_modify_qp: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int modify_qp(struct resources *res, struct rdma_cm_id *cm_id)
{
	if (cm_modify_qp(res, cm_id, IBV_QPS_INIT)) {
		err("modify QP to INIT\n");
		return -1;
	}

	if (post_recv_all(res))
		return -1;

	if (cm_modify_qp(res, cm_id, IBV_QPS_RTR)) {
		err("modify QP to RTR\n");
		return -1;
	}

	if (cm_modify_qp(res, cm_id, IBV_QPS_RTS)) {
		err("modify QP to RTS\n");
		return -1;
	}

	return 0;
}

static int cm_connect_client(struct resources *res,
			     struct rdma_conn_param *conn_param)
{
	struct rdma_cm_id *cm_id = res->cm_id;

	if (rdma_connect(cm_id, conn_param)) {
		err("rdma_connect: %s\n", strerror(errno));
		return -1;
	}

	if (modify_qp(res, cm_id))
		return -1;

	if (rdma_establish(cm_id)) {
		err("rdma_establish: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int cm_connect_server(struct resources *res,
			     struct rdma_conn_param *conn_param)
{
	struct rdma_cm_id *cm_id = res->child_cm_id;

	if (modify_qp(res, cm_id))
		return -1;

	if (rdma_accept(cm_id, conn_param)) {
		err("rdma_accept: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int cm_connect(struct resources *res)
{
	struct rdma_conn_param conn_param = {
		.responder_resources = 1,
		.initiator_depth = 1,
		.retry_count = 7,
		.rnr_retry_count = 7,
		.qp_num = res->qp->qp_num,
	};

	if (is_client())
		return cm_connect_client(res, &conn_param);

	return cm_connect_server(res, &conn_param);
}

static int cm_disconnect(struct resources *res)
{
	struct rdma_cm_id *cm_id = is_client() ? res->cm_id : res->child_cm_id;

	if (modify_qp_to_err(res->qp)) {
		err("modify QP to ERR\n");
		return -1;
	}

	if (rdma_disconnect(cm_id)) {
		err("rdma_disconnect: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static const char *addr_to_str(struct sockaddr *addr)
{

	static char str_buf[INET6_ADDRSTRLEN];
	const char *str = NULL;

	if (addr->sa_family == AF_INET)
		str = inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, str_buf, sizeof(str_buf));
	else if (addr->sa_family == AF_INET6)
		str = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, str_buf, sizeof(str_buf));

	if (str == NULL) {
		str_buf[0] = '\0';
		str = str_buf;
	}

	return str;
}

static void print_config(void) {
	info(" -----------------Configuration------------------\n");
	if (conf.src_addr.ss_family)
		info(" Local IP : %s\n", addr_to_str((struct sockaddr *)&conf.src_addr));
	if (conf.dst_addr.ss_family)
		info(" Remote IP : %s\n", addr_to_str((struct sockaddr *)&conf.dst_addr));

	info(" port : %lu\n", conf.port);

	info(" Block size : %u\n", SERVER_DATA_SIZE);
	info(" I/O size : %d\n", conf.nb * SERVER_DATA_SIZE);
	info(" Queue depth : %d\n", conf.queue_depth);
	info(" ------------------------------------------------\n\n");
}

static void usage(const char *argv0) {
	info("Usage:\n");
	info(" %s [<options>]               start a server and wait for connection\n", argv0);
	info(" %s [<options>] <addr>        connect to server at <addr>\n", argv0);
	info("\n");
	info("Options:\n");
	info(" -h, --help                   print this message\n");
	info(" -S, --src-addr <addr>        source IP or hostname\n");
	info(" -p, --port <port>            listen on/connect to port <port> (default 19875)\n");
	info(" -n, --number-of-blocks <NB>  Number of blocks per RDMA operation (default 8)\n");
	info(" -q, --queue-depth <num>      number of simultaneous requests per QP that "
					   "a client can send to the server.\n");
	info(" -t, --time <num>             stop after <num> seconds (default 1)\n");
	info(" -c, --iters <num>            stop after <num> iterations (default unlimited)\n");
	info(" -l, --log-level <lvl>        0 - ERROR, 1 - INFO, 2 - DEBUG\n");
}

static int get_sockaddr(const char *host, struct sockaddr *addr)
{
	struct addrinfo *res;
	int rc;

	rc = getaddrinfo(host, NULL, NULL, &res);
	if (rc) {
		err("getaddrinfo(%s): %s\n", host, gai_strerror(rc));
		return -1;
	}

	if (res->ai_family == PF_INET)
		memcpy(addr, res->ai_addr, sizeof(struct sockaddr_in));
	else if (res->ai_family == PF_INET6)
		memcpy(addr, res->ai_addr, sizeof(struct sockaddr_in6));
	else
		rc = -1;

	freeaddrinfo(res);

	return rc;
}

int main(int argc, char *argv[]) 
{
	struct resources res = {};
	int rc = 1;

	/* parse the command line parameters */
	while (1) {
		int c;
		static struct option long_options[] = {
			{ .name = "help",		.has_arg = 1, .val = 'h' },
			{ .name = "src-addr",		.has_arg = 1, .val = 'S' },
			{ .name = "port",		.has_arg = 1, .val = 'p' },
			{ .name = "number-of-blocks",	.has_arg = 1, .val = 'n' },
			{ .name = "queue-depth",	.has_arg = 1, .val = 'q' },
			{ .name = "time",		.has_arg = 1, .val = 't' },
			{ .name = "iters",		.has_arg = 1, .val = 'c' },
			{ .name = "log-level",		.has_arg = 1, .val = 'l' },
			{ .name = NULL,			.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "hS:p:n:q:t:c:l:", long_options,
				NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'S':
			rc = get_sockaddr(optarg, (struct sockaddr *)&conf.src_addr);
			if (rc) {
				err("Invalid src-addr %s\n", optarg);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'p':
			conf.port = strtoul(optarg, NULL, 0);
			if (conf.port == 0 || conf.port > UINT16_MAX) {
				err("Invalid port %s\n", optarg);
				usage(argv[0]);
				return -1;
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
	if (optind == argc - 1) {
		rc = get_sockaddr(argv[optind], (struct sockaddr *)&conf.dst_addr);
		if (rc) {
			err("Invalid dst-addr %s\n", optarg);
			usage(argv[0]);
			return -1;
		}
	} else if (optind < argc) {
		usage(argv[0]);
		return 1;
	}

	print_config();

	if (rdma_create_id(NULL, &res.cm_id, NULL, RDMA_PS_TCP)) {
		rc = errno;
		err("rdma_create_id: %s\n", strerror(errno));
		return -1;
	}

	rc = cm_bind(&res);
	if (rc)
		goto free_res_and_exit;

	rc = resources_create(&res);
	if (rc) {
		if (skip) {
			info("Signature pipelining feature is not supported by the specified RDMA device\n");
			rc = 0;
		}
		goto free_res_and_exit;
	}

	rc = cm_connect(&res);
	if (rc)
		goto free_res_and_exit;

	if (set_signal_handler())
		goto free_res_and_exit;

	if (is_client()) {
		alarm(conf.time);
		rc = client(&res);
	} else {
		alarm(conf.time + 1);
		rc = server(&res);
	}
	if (rc)
		goto free_res_and_exit;


	rc = cm_disconnect(&res);
	if (rc)
		goto free_res_and_exit;

	// avoid crash while calculate time/comp bellow
	if (!res.comps_counter) {
		res.comps_counter = 1;
	}

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
free_res_and_exit:
	if (resources_destroy(&res))
		rc = -1;

	return rc;
}
