/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2018, Mellanox Technologies
 * All rights reserved.
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
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
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#include <rdma/rdma_cma.h>
#include <netdb.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define info(format, arg...)	fprintf(stdout, format, ##arg)

#define err(format, arg...)	fprintf(stderr, "ERROR: " format, ##arg)

static bool skip = false;

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

/* structure of test parameters */
struct {
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	unsigned long int port;
	int block_size;
	int nb;
	int interleave;
	const struct signature_ops *sig;
	int corrupt_data;
	int corrupt_app_tag;
	int corrupt_ref_tag;
	int corrupt_offset;
} config = {
	.port			= 19875,
	.block_size		= 512,
	.nb			= 8,
	.interleave		= 0,
	.corrupt_data		= 0,
	.corrupt_offset		= -1,
	.corrupt_app_tag	= 0,
	.corrupt_ref_tag	= 0,
};

static inline int is_client()
{
	return config.dst_addr.ss_family;
}

/* structure of system resources */
struct resources {
	struct rdma_cm_id *cm_id;	/* connection on client side,*/
					/* listener on server side. */
	struct rdma_cm_id *child_cm_id;	/* connection on server side */
	struct ibv_context *ib_ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_wc wc;

	struct ibv_mr *send_mr;	/* MR for send buffer */
	struct ibv_mr *recv_mr;	/* MR for recv buffer */
	struct ibv_mr *data_mr;	/* MR for data buffer */
	struct ibv_mr *pi_mr;	/* MR for protection information buffer */
	struct mlx5dv_mkey *sig_mkey;

	uint8_t *send_buf;
	uint8_t *recv_buf;
	uint8_t *data_buf;
	size_t data_buf_size;
	uint8_t *pi_buf;
	size_t pi_buf_size;
	int sock; /* TCP socket file descriptor */
};

static int is_sig_supported(struct ibv_context *ibv_ctx,
			    uint32_t prot,
			    uint16_t sig)
{
	struct mlx5dv_context ctx = {
		.comp_mask = MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD,
	};
	int rc;

	rc = mlx5dv_query_device(ibv_ctx, &ctx);
	if (rc) {
		err("mlx5dv_query_device: %s\n", strerror(rc));
		return -1;
	}

	switch (prot) {
	case MLX5DV_SIG_PROT_CAP_T10DIF:
		if (!(ctx.sig_caps.t10dif_bg & sig))
			return 0;
		break;
	case MLX5DV_SIG_PROT_CAP_CRC:
		if (!(ctx.sig_caps.crc_type & sig))
			return 0;
		break;
	default:
		err("unknown prot type %u\n", prot);
		return -1;
	}

	return 1;
}

static void _set_sig_domain_crc32(enum mlx5dv_sig_crc_type type,
				  struct mlx5dv_sig_block_domain *domain,
				  void *sig)
{
	struct mlx5dv_sig_crc *crc = sig;

	memset(domain, 0, sizeof(*domain));
	memset(crc, 0, sizeof(*crc));

	domain->sig_type = MLX5DV_SIG_TYPE_CRC;
	domain->block_size = (config.block_size == 512) ?
				     MLX5DV_BLOCK_SIZE_512 :
				     MLX5DV_BLOCK_SIZE_4096;

	crc->type = type;
	crc->seed = 0xffffffff;
	domain->sig.crc = crc;
}

static void set_sig_domain_crc32(struct mlx5dv_sig_block_domain *domain, void *sig)
{
	_set_sig_domain_crc32(MLX5DV_SIG_CRC_TYPE_CRC32, domain, sig);
}

static void set_sig_domain_crc32c(struct mlx5dv_sig_block_domain *domain, void *sig)
{
	_set_sig_domain_crc32(MLX5DV_SIG_CRC_TYPE_CRC32C, domain, sig);
}

static void dump_pi_crc32(void *pi)
{
	uint32_t crc = ntohl(*(uint32_t *)pi);

	info("crc32 0x%x\n", crc);
}

static int is_crc32_supported(struct ibv_context *ctx)
{
	return is_sig_supported(ctx, MLX5DV_SIG_PROT_CAP_CRC, MLX5DV_SIG_CRC_TYPE_CAP_CRC32);
}

static int is_crc32c_supported(struct ibv_context *ctx)
{
	return is_sig_supported(ctx, MLX5DV_SIG_PROT_CAP_CRC, MLX5DV_SIG_CRC_TYPE_CAP_CRC32C);
}

struct t10dif_pi {
	uint16_t guard;
	uint16_t app_tag;
	uint32_t ref_tag;

} __attribute__((packed));

static void dump_pi_t10dif(void *pi_ptr)
{
	struct t10dif_pi *pi = pi_ptr;

	info("t10dif { guard 0x%x, application tag 0x%x, reference tag 0x%x }\n",
	     ntohs(pi->guard), ntohs(pi->app_tag), ntohl(pi->ref_tag));
}

static void set_sig_domain_t10dif_type1_2(struct mlx5dv_sig_block_domain *domain,
					  void *sig)
{
	struct mlx5dv_sig_t10dif *dif = sig;

	memset(dif, 0, sizeof(*dif));
	dif->bg_type = MLX5DV_SIG_T10DIF_CRC;
	dif->bg = 0xffff;
	dif->app_tag = 0x5678;
	dif->ref_tag = 0xabcdef90;
	dif->flags = MLX5DV_SIG_T10DIF_FLAG_REF_REMAP |
		     MLX5DV_SIG_T10DIF_FLAG_APP_ESCAPE;

	memset(domain, 0, sizeof(*domain));
	domain->sig.dif = dif;
	domain->sig_type = MLX5DV_SIG_TYPE_T10DIF;
	domain->block_size = (config.block_size == 512) ?
				     MLX5DV_BLOCK_SIZE_512 :
				     MLX5DV_BLOCK_SIZE_4096;
}

static void set_sig_domain_t10dif_type3(struct mlx5dv_sig_block_domain *domain,
					void *sig)
{
	struct mlx5dv_sig_t10dif *dif = sig;

	memset(dif, 0, sizeof(*dif));
	dif->bg_type = MLX5DV_SIG_T10DIF_CRC;
	dif->bg = 0xffff;
	dif->app_tag = 0x5678;
	dif->ref_tag = 0xabcdef90;
	dif->flags = MLX5DV_SIG_T10DIF_FLAG_APP_REF_ESCAPE;

	memset(domain, 0, sizeof(*domain));
	domain->sig.dif = dif;
	domain->sig_type = MLX5DV_SIG_TYPE_T10DIF;
	domain->block_size = (config.block_size == 512) ?
				     MLX5DV_BLOCK_SIZE_512 :
				     MLX5DV_BLOCK_SIZE_4096;
}

static int is_t10dif_supported(struct ibv_context *ctx)
{
	return is_sig_supported(ctx, MLX5DV_SIG_PROT_CAP_T10DIF, MLX5DV_SIG_T10DIF_BG_CAP_CRC);
}

enum signature_types {
	SIG_TYPE_CRC32 = 0,
	SIG_TYPE_CRC32C,
	SIG_TYPE_T10DIF_TYPE1,
	SIG_TYPE_T10DIF_TYPE2,
	SIG_TYPE_T10DIF_TYPE3,

	SIG_TYPE_MAX,
};

struct signature_ops {
	const char *	name;
	size_t		pi_size;
	void		(*set_sig_domain)(struct mlx5dv_sig_block_domain *, void *);
	void		(*dump_pi)(void *pi);
	uint8_t		check_mask;
	int		(*is_supported)(struct ibv_context *ctx);
};

const struct signature_ops sig_ops[SIG_TYPE_MAX] = {
	[SIG_TYPE_CRC32] = {
		.name		= "crc32",
		.pi_size	= 4,
		.set_sig_domain	= set_sig_domain_crc32,
		.dump_pi	= dump_pi_crc32,
		.check_mask	= MLX5DV_SIG_MASK_CRC32,
		.is_supported	= is_crc32_supported,
	},
	[SIG_TYPE_CRC32C] = {
		.name		= "crc32c",
		.pi_size	= 4,
		.set_sig_domain	= set_sig_domain_crc32c,
		.dump_pi	= dump_pi_crc32,
		.check_mask	= MLX5DV_SIG_MASK_CRC32C,
		.is_supported	= is_crc32c_supported,
	},
	[SIG_TYPE_T10DIF_TYPE1] = {
		.name		= "t10dif-type1",
		.pi_size	= 8,
		.set_sig_domain	= set_sig_domain_t10dif_type1_2,
		.dump_pi	= dump_pi_t10dif,
		.check_mask	= MLX5DV_SIG_MASK_T10DIF_GUARD |
				  MLX5DV_SIG_MASK_T10DIF_APPTAG |
				  MLX5DV_SIG_MASK_T10DIF_REFTAG,
		.is_supported	= is_t10dif_supported,
	},
	[SIG_TYPE_T10DIF_TYPE2] = {
		.name		= "t10dif-type2",
		.pi_size	= 8,
		.set_sig_domain	= set_sig_domain_t10dif_type1_2,
		.dump_pi	= dump_pi_t10dif,
		.check_mask	= MLX5DV_SIG_MASK_T10DIF_GUARD |
				  MLX5DV_SIG_MASK_T10DIF_APPTAG |
				  MLX5DV_SIG_MASK_T10DIF_REFTAG,
		.is_supported	= is_t10dif_supported,
	},
	[SIG_TYPE_T10DIF_TYPE3] = {
		.name		= "t10dif-type3",
		.pi_size	= 8,
		.set_sig_domain	= set_sig_domain_t10dif_type3,
		.dump_pi	= dump_pi_t10dif,
		.check_mask	= MLX5DV_SIG_MASK_T10DIF_GUARD |
				  MLX5DV_SIG_MASK_T10DIF_APPTAG |
				  MLX5DV_SIG_MASK_T10DIF_REFTAG,
		.is_supported	= is_t10dif_supported,
	},
};

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

static const char *wc_opcode_str(enum ibv_wc_opcode opcode)
{
	const char *str;

	switch (opcode) {
	case IBV_WC_RDMA_WRITE:
		str = "RDMA_WRITE";
		break;
	case IBV_WC_SEND:
		str = "SEND";
		break;
	case IBV_WC_RDMA_READ:
		str = "RDMA_READ";
		break;
	case IBV_WC_LOCAL_INV:
		str = "LOCAL_INV";
		break;
	case IBV_WC_RECV:
		str = "RECV";
		break;
	case IBV_WC_DRIVER1:
		str = "DRIVER1";
		break;
	default:
		str = "UNKNOWN";
	};

	return str;
}

static int poll_completion(struct resources *res, enum ibv_wc_opcode expected)
{
	unsigned long start_time_msec;
	unsigned long cur_time_msec;
	struct timeval cur_time;
	struct ibv_wc *wc = &res->wc;
	int poll_result;

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
		err("poll CQ failed\n");
		return -1;
	}
	if (poll_result == 0) {
		err("poll CQ timeout\n");
		return -1;
	}
	if (wc->status != IBV_WC_SUCCESS) {
		err("CQE status %s, opcode %s\n", ibv_wc_status_str(wc->status),
		    wc_opcode_str(wc->opcode));
		return -1;
	}
	if (wc->opcode != expected) {
		err("CQE opcode (%s) != expected opcode (%s)\n",
		    wc_opcode_str(wc->opcode), wc_opcode_str(expected));
		return -1;
	}
	info("CQE status %s, opcode %s\n", ibv_wc_status_str(wc->status),
	     wc_opcode_str(wc->opcode));

	return 0;
}

static const char *send_opcode_str(int opcode)
{
	const char *str;

	switch (opcode) {
	case IBV_WR_RDMA_WRITE:
		str = "RDMA_WRITE";
		break;
	case IBV_WR_SEND:
		str = "SEND";
		break;
	case IBV_WR_RDMA_READ:
		str = "RDMA_READ";
		break;
	case IBV_WR_LOCAL_INV:
		str = "LOCAL_INV";
		break;
	case IBV_WR_DRIVER1:
		str = "DRIVER1";
		break;
	default:
		str = "UNKNOWN";
	};

	return str;
}

static int post_send(struct resources *res, int opcode, const struct msg_t *req)
{
	struct ibv_send_wr sr;
	struct ibv_sge sge;
	struct ibv_send_wr *bad_wr = NULL;
	int rc;

	/* prepare the scatter/gather entry */
	if (!req) {
		sge.addr = (uintptr_t)res->send_mr->addr;
		sge.length = MSG_SIZE;
		sge.lkey = res->send_mr->lkey;
	} else {
		sge.addr = 0;
		/* length is calculated according to wire domain */
		sge.length = (config.block_size + config.sig->pi_size) * config.nb;
		sge.lkey = res->sig_mkey->lkey;
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

	rc = ibv_post_send(res->qp, &sr, &bad_wr);
	if (rc) {
		err("ibv_post_send: opcode %s: %s\n", send_opcode_str(opcode),
		    strerror(rc));
		return -1;
	}

	info("Post SEND WR, opcode %s\n", send_opcode_str(opcode));

	return 0;
}

static int post_receive(struct resources *res)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)res->recv_mr->addr,
		.length = MSG_SIZE,
		.lkey = res->recv_mr->lkey
	};
	struct ibv_recv_wr wr = {
		.sg_list = &sge,
		.num_sge = 1
	};
	struct ibv_recv_wr *bad_wr;
	int rc;

	rc = ibv_post_recv(res->qp, &wr, &bad_wr);
	if (rc) {
		err("ibv_post_recv: %s\n", strerror(rc));
		return -1;
	}

	info("Post receive WR\n");

	return 0;
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
	if (!mkey)
		err("mlx5dv_create_mkey: %s\n", strerror(errno));

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

enum sig_mode {
	SIG_MODE_INSERT,
	SIG_MODE_CHECK,
	SIG_MODE_STRIP,
};

static int configure_sig_mkey(struct resources *res,
			      enum sig_mode mode,
			      struct mlx5dv_sig_block_attr *sig_attr)
{
	struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
	struct mlx5dv_qp_ex *dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
	struct mlx5dv_mkey *mkey = res->sig_mkey;
	struct mlx5dv_mkey_conf_attr conf_attr = {};
	uint32_t access_flags = IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE;
	struct ibv_sge sge;
	struct mlx5dv_mr_interleaved mr_interleaved[2];

	ibv_wr_start(qpx);
	qpx->wr_id = 0;
	qpx->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

	mlx5dv_wr_mkey_configure(dv_qp, mkey, 3, &conf_attr);
	mlx5dv_wr_set_mkey_access_flags(dv_qp, access_flags);

	if ((!res->pi_buf) ||
	    (mode == SIG_MODE_INSERT) ||
	    (mode == SIG_MODE_STRIP)) {
		sge.addr = (uintptr_t)res->data_mr->addr;
		sge.lkey = res->data_mr->lkey;
		if ((mode == SIG_MODE_INSERT) ||
		    (mode == SIG_MODE_STRIP) ||
		    (!config.interleave))
			sge.length = config.block_size * config.nb;
		else
			sge.length = res->data_mr->length;
		mlx5dv_wr_set_mkey_layout_list(dv_qp, 1, &sge);
	} else {
		/* data */
		mr_interleaved[0].addr = (uintptr_t)res->data_mr->addr;
		mr_interleaved[0].bytes_count = config.block_size;
		mr_interleaved[0].bytes_skip = 0;
		mr_interleaved[0].lkey = res->data_mr->lkey;
		/* protection */
		mr_interleaved[1].addr = (uintptr_t)res->pi_mr->addr;
		mr_interleaved[1].bytes_count = config.sig->pi_size;
		mr_interleaved[1].bytes_skip = 0;
		mr_interleaved[1].lkey = res->pi_mr->lkey;

		mlx5dv_wr_set_mkey_layout_interleaved(dv_qp, config.nb, 2,
						      mr_interleaved);
	}
	mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);

	return ibv_wr_complete(qpx);
}

static int reg_sig_mkey(struct resources *res, enum sig_mode mode)
{
	union {
		struct mlx5dv_sig_t10dif t10dif;
		struct mlx5dv_sig_crc crc;
	} mem_sig;
	union {
		struct mlx5dv_sig_t10dif t10dif;
		struct mlx5dv_sig_crc crc;
	} wire_sig;
	struct mlx5dv_sig_block_domain mem;
	struct mlx5dv_sig_block_domain wire;
	struct mlx5dv_sig_block_attr sig_attr = {
		.mem = &mem,
		.wire = &wire,
		.check_mask = config.sig->check_mask,
	};

	switch (mode) {
	case SIG_MODE_INSERT:
	case SIG_MODE_STRIP:
		sig_attr.mem = NULL;
		config.sig->set_sig_domain(&wire, &wire_sig);
		break;
	case SIG_MODE_CHECK:
		config.sig->set_sig_domain(&mem, &mem_sig);
		config.sig->set_sig_domain(&wire, &wire_sig);
		break;
	default:
		break;
	}

	if (configure_sig_mkey(res, mode, &sig_attr))
		return -1;

	info("Post mkey configure WR, opcode DRIVER1\n");

	if (poll_completion(res, IBV_WC_DRIVER1)) {
		err("Failed to configure sig MKEY\n");
		return -1;
	}
	info("Sig MKEY is configured\n");

	return 0;
}

static int check_sig_mkey(struct mlx5dv_mkey *mkey)
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
		break;
	}

	if (!sig_err)
		info("SIG status: OK\n");
	else
		info("SIG ERROR: %s: expected 0x%lx, actual 0x%lx, offset %lu\n",
		     sig_err_str, err_info.err.sig.expected_value,
		     err_info.err.sig.actual_value, err_info.err.sig.offset);

	return sig_err;
}

static int inv_sig_mkey(struct resources *res)
{
	struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
	int rc;

	ibv_wr_start(qpx);
	qpx->wr_id = 0;
	qpx->wr_flags = IBV_SEND_SIGNALED;
	ibv_wr_local_inv(qpx, res->sig_mkey->rkey);
	rc = ibv_wr_complete(qpx);
	if (rc) {
		err("Local invalidate sig MKEY: %s\n", strerror(rc));
		return -1;
	}

	if (poll_completion(res, IBV_WC_LOCAL_INV)) {
		err("Failed to invalidete sig MKEY\n");
		return -1;
	}

	info("Sig MKEY is invalidated\n");

	return rc;
}

static int dealloc_pd(struct ibv_pd **pd)
{
	int rc;

	if (!*pd)
		return 0;

	rc = ibv_dealloc_pd(*pd);
	if (rc) {
		err("ibv_dealloc_pd: %s\n", strerror(rc));
		rc = -1;
	}
	*pd = NULL;

	return rc;
}

static int destroy_cq(struct ibv_cq **cq)
{
	int rc;

	if (!*cq)
		return 0;

	rc = ibv_destroy_cq(*cq);
	if (rc) {
		err("ibv_destroy_cq: %s\n", strerror(rc));
		rc = -1;
	}
	*cq = NULL;

	return rc;
}

static int destroy_qp(struct ibv_qp **qp)
{
	uint32_t qpn;
	int rc;

	if (!*qp)
		return 0;

	qpn = (*qp)->qp_num;

	rc = ibv_destroy_qp(*qp);
	if (rc) {
		err("ibv_destroy_qp: QP 0x%x: %s\n", qpn, strerror(rc));
		rc = -1;
	}
	*qp = NULL;

	return rc;
}

static struct ibv_qp *create_qp(struct resources *res)
{
	struct ibv_qp_init_attr_ex qp_attr = {};
	struct mlx5dv_qp_init_attr mlx5_qp_attr = {};
	struct ibv_qp *qp;

	/* create the Queue Pair */
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.sq_sig_all = 0;
	qp_attr.send_cq = res->cq;
	qp_attr.recv_cq = res->cq;
	qp_attr.cap.max_send_wr = 4;
	qp_attr.cap.max_recv_wr = 1;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;
	qp_attr.cap.max_inline_data = 512;

	qp_attr.pd = res->pd;
	qp_attr.comp_mask = IBV_QP_INIT_ATTR_PD;
	qp_attr.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
	qp_attr.send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE |
				 IBV_QP_EX_WITH_SEND |
				 IBV_QP_EX_WITH_RDMA_READ |
				 IBV_QP_EX_WITH_LOCAL_INV;

	/* signature specific attributes */
	mlx5_qp_attr.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS;
	mlx5_qp_attr.send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE;

	qp = mlx5dv_create_qp(res->ib_ctx, &qp_attr, &mlx5_qp_attr);
	if (!qp)
		err("mlx5dv_create_qp: %s\n", strerror(errno));

	return qp;
}

static void resources_init(struct resources *res)
{
	memset(res, 0, sizeof *res);

	res->data_buf_size = config.block_size * config.nb;

	if (config.interleave)
		res->data_buf_size += config.sig->pi_size * config.nb;
	else
		res->pi_buf_size = config.sig->pi_size * config.nb;
}

static int free_mr(struct ibv_mr **mr)
{
	void *ptr;
	int rc;

	if (!*mr)
		return 0;

	ptr = (*mr)->addr;
	rc = ibv_dereg_mr(*mr);
	if (rc)
		err("ibv_dereg_mr: %s\n", strerror(rc));

	*mr = NULL;
	free(ptr);

	return rc;
}

struct ibv_mr * alloc_mr(struct ibv_pd *pd, size_t size)
{
	int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
		       IBV_ACCESS_REMOTE_WRITE;
	void *ptr;
	struct ibv_mr *mr;

	ptr = malloc(size);
	if (!ptr) {
		err("calloc: %s\n", strerror(errno));
		return NULL;
	}
	memset(ptr, 1, size);

	mr = ibv_reg_mr(pd, ptr, size, mr_flags);
	if (!mr) {
		err("ibv_reg_mr: %s\n", strerror(errno));
		free(ptr);
		return NULL;
	}

	return mr;
}

static int resources_destroy(struct resources *res)
{
	int rc = 0;

	if (destroy_qp(&res->qp))
		rc = -1;

	if (destroy_sig_mkey(&res->sig_mkey))
		rc = -1;

	if (free_mr(&res->pi_mr))
		rc = -1;

	if (free_mr(&res->data_mr))
		rc = -1;

	if (free_mr(&res->send_mr))
		rc = -1;

	if (free_mr(&res->recv_mr))
		rc = -1;

	if (destroy_cq(&res->cq))
		rc = -1;

	if (dealloc_pd(&res->pd))
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

static int resources_create(struct resources *res)
{
	int rc;
	int cq_size = 0;

	if (is_client())
		res->ib_ctx = res->cm_id->verbs;
	else
		res->ib_ctx = res->child_cm_id->verbs;

	if (!mlx5dv_is_supported(res->ib_ctx->device)) {
		err("device %s doesn't support DV\n",
		    ibv_get_device_name(res->ib_ctx->device));
		skip = true;
		goto err_exit;
	}

	rc = config.sig->is_supported(res->ib_ctx);
	if (rc < 0)
		return -1;

	if (!rc) {
		err("Signature feature is not supported by device %s\n",
		    ibv_get_device_name(res->ib_ctx->device));
		skip = true;
		return -1;
	}

	res->pd = ibv_alloc_pd(res->ib_ctx);
	if (!res->pd) {
		err("ibv_alloc_pd: %s\n", strerror(errno));
		goto err_exit;
	}

	cq_size = 16;
	res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
	if (!res->cq) {
		err("ibv_create_cq: size %u: %s\n", cq_size, strerror(errno));
		goto err_exit;
	}

	res->send_mr = alloc_mr(res->pd, MSG_SIZE);
	if (!res->send_mr)
		goto err_exit;

	res->recv_mr = alloc_mr(res->pd, MSG_SIZE);
	if (!res->recv_mr)
		goto err_exit;

	res->data_mr = alloc_mr(res->pd, res->data_buf_size);
	if (!res->data_mr)
		goto err_exit;

	if (res->pi_buf_size) {
		res->pi_mr = alloc_mr(res->pd, res->pi_buf_size);
		if (!res->pi_mr)
			goto err_exit;

		res->pi_buf = res->pi_mr->addr;
	}

	res->recv_buf = res->recv_mr->addr;
	res->send_buf = res->send_mr->addr;
	res->data_buf = res->data_mr->addr;

	res->sig_mkey = create_sig_mkey(res);
	if (!res->sig_mkey)
		goto err_exit;

	res->qp = create_qp(res);
	if (!res->qp)
		goto err_exit;

	return 0;
err_exit:
	resources_destroy(res);
	return -1;
}

static int send_repl(struct resources *res, uint8_t type, uint32_t status)
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

	rc = poll_completion(res, IBV_WC_SEND);
	if (rc)
		return rc;

	return rc;
}

static int handle_write_req(struct resources *res,
			    const struct msg_t *req)
{
	int sig_err;

	if (reg_sig_mkey(res, SIG_MODE_CHECK))
		return -1;

	if (post_send(res, IBV_WR_RDMA_READ, req))
		return -1;

	if (poll_completion(res, IBV_WC_RDMA_READ))
		return -1;

	sig_err = check_sig_mkey(res->sig_mkey);
	if (sig_err < 0)
		return -1;

	if (inv_sig_mkey(res))
		return -1;

	if (post_receive(res))
		return -1;

	if (send_repl(res, MSG_TYPE_WRITE_REP,
		      sig_err ? MSG_REP_STATUS_FAIL : MSG_REP_STATUS_OK))
		return -1;

	return 0;
}

static uint8_t *find_corrupt_pos(struct resources *res, int offset)
{
	uint8_t *pos;
	int block_len = config.block_size + config.sig->pi_size;

	if (offset >= block_len * config.nb)
		return NULL;

	if (config.interleave) {
		pos = res->data_buf + offset;
	} else {
		if (offset % block_len < config.block_size) {
			// corrupt in data
			pos = res->data_buf +
			      offset / block_len * config.block_size +
			      offset % block_len;
		} else {
			// corrupt in protection information
			pos = res->pi_buf +
			      offset / block_len * config.sig->pi_size +
			      (offset % block_len - config.block_size);
		}
	}
	return pos;
}

static int handle_read_req(struct resources *res,
			   const struct msg_t *req)
{
	uint8_t *corrupt_pos;
	int sig_err;

	if (reg_sig_mkey(res, SIG_MODE_CHECK))
		return -1;

	if (config.corrupt_offset >= 0) {
		corrupt_pos = find_corrupt_pos(res, config.corrupt_offset);
		if (!corrupt_pos) {
			err("input offset is not correct\n");
			return -1;
		}
		// corrupt the data in the position
		*corrupt_pos = ~(*corrupt_pos);
	}

	if (post_send(res, IBV_WR_RDMA_WRITE, req))
		return -1;

	if (poll_completion(res, IBV_WC_RDMA_WRITE))
		return -1;

	sig_err = check_sig_mkey(res->sig_mkey);
	if (sig_err < 0)
		return -1;

	if (inv_sig_mkey(res))
		return -1;

	if (post_receive(res))
		return -1;

	if (send_repl(res, MSG_TYPE_READ_REP,
		      sig_err ? MSG_REP_STATUS_FAIL : MSG_REP_STATUS_OK))
		return -1;

	return 0;
}

static int server(struct resources *res)
{
	struct msg_t *msg = (struct msg_t *)res->recv_buf;

	while (1) {
		if (poll_completion(res, IBV_WC_RECV))
			return -1;

		switch (msg->type) {
		case MSG_TYPE_WRITE_REQ:
			if (handle_write_req(res, msg))
				return -1;
			break;
		case MSG_TYPE_READ_REQ:
			if (handle_read_req(res, msg))
				return -1;
			break;
		case MSG_TYPE_CLOSE_CONN:
			return 0;
		default:
			err("invalid message type 0x%x\n", msg->type);
			return -1;
		}

	}

	return 0;
}


static int client(struct resources *res)
{
	struct msg_t *msg;
	int i;

	/* ============ WRITE OPERATION ==========================  */

	if (reg_sig_mkey(res, SIG_MODE_INSERT))
		return -1;

	msg = (struct msg_t *)res->send_buf;
	msg->type = MSG_TYPE_WRITE_REQ;
	msg->data.req.addr = 0; /* sig MR is a zero-based MR */
	msg->data.req.rkey = htonl(res->sig_mkey->rkey);

	info("Send write request\n");

	if (post_send(res, IBV_WR_SEND, NULL))
		return -1;

	if (poll_completion(res, IBV_WC_SEND))
		return -1;

	if (poll_completion(res, IBV_WC_RECV))
		return -1;

	msg = (struct msg_t *)res->recv_buf;
	if (msg->type != MSG_TYPE_WRITE_REP) {
		err("Unexpected message type 0x%x", msg->type);
		return -1;
	}

        info("WRITE_REPLY: status %s\n",
             (ntohl(msg->data.rep.status) == MSG_REP_STATUS_OK) ? "OK"
                                                                : "FAIL");

	if (check_sig_mkey(res->sig_mkey) < 0)
		return -1;

	if (inv_sig_mkey(res))
		return -1;

	/* ============ READ OPERATION ==========================  */

	if (post_receive(res))
		return -1;

	if (reg_sig_mkey(res, SIG_MODE_CHECK))
		return -1;

	msg = (struct msg_t *)res->send_buf;
	memset(msg, 0, sizeof(*msg));
	msg->type = MSG_TYPE_READ_REQ;
	msg->data.req.addr = 0; /* sig MR is a zero-based MR */
	msg->data.req.rkey = htonl(res->sig_mkey->rkey);

	if (post_send(res, IBV_WR_SEND, NULL))
		return -1;

	if (poll_completion(res, IBV_WC_SEND))
		return -1;

	if (poll_completion(res, IBV_WC_RECV))
		return -1;

	msg = (struct msg_t *)res->recv_buf;
	if (msg->type != MSG_TYPE_READ_REP) {
		err("Unexpected message type 0x%x", msg->type);
		return -1;
	}

        info("READ_REPLY: status %s\n",
             (ntohl(msg->data.rep.status) == MSG_REP_STATUS_OK) ? "OK"
                                                                : "FAIL");

	if (check_sig_mkey(res->sig_mkey) < 0)
		return -1;

	info("Dump PI:\n");
	for (i = 0; i < config.nb; i++) {
		uint8_t *pi;
		if (config.interleave)
			pi = res->data_buf + (config.block_size * (i + 1)) +
				config.sig->pi_size * i;
		else
			pi =  res->pi_buf + config.sig->pi_size * i;

		info("block[%d] : ", i);
		config.sig->dump_pi(pi);
	}

	if (inv_sig_mkey(res))
		return -1;

	/* ============== Send close connection ===================== */

	msg = (struct msg_t *)res->send_buf;
	memset(msg, 0, sizeof(*msg));
	msg->type = MSG_TYPE_CLOSE_CONN;

	if (post_send(res, IBV_WR_SEND, NULL))
		return -1;

	if (poll_completion(res, IBV_WC_SEND))
		return -1;

	return 0;
}

static int cm_bind_client(struct resources *res)
{
	struct rdma_cm_id *cm_id = res->cm_id;
	int rc;

	if (config.dst_addr.ss_family == AF_INET)
		((struct sockaddr_in *)&config.dst_addr)->sin_port = htobe16(config.port);
	else
		((struct sockaddr_in6 *)&config.dst_addr)->sin6_port = htobe16(config.port);

	if (config.src_addr.ss_family)
		rc = rdma_resolve_addr(cm_id, (struct sockaddr *)&config.src_addr,
				       (struct sockaddr *)&config.dst_addr, 2000);
	else
		rc = rdma_resolve_addr(cm_id, NULL, (struct sockaddr *)&config.dst_addr, 2000);

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
	if (!config.src_addr.ss_family)
		config.src_addr.ss_family = AF_INET;

	if (config.src_addr.ss_family == AF_INET)
		((struct sockaddr_in *)&config.src_addr)->sin_port = htobe16(config.port);
	else
		((struct sockaddr_in6 *)&config.src_addr)->sin6_port = htobe16(config.port);

	if (rdma_bind_addr(cm_id, (struct sockaddr *)&config.src_addr)) {
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

	if (post_receive(res))
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
		str = inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr,
				str_buf, sizeof(str_buf));
	else if (addr->sa_family == AF_INET6)
		str = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr,
				str_buf, sizeof(str_buf));

	if (str == NULL) {
		str_buf[0] = '\0';
		str = str_buf;
	}

	return str;
}

static void print_config(void)
{
	info(" ----------------------------------------------\n");
	if (config.src_addr.ss_family)
		info(" Local IP : %s\n", addr_to_str((struct sockaddr *)&config.src_addr));
	if (config.dst_addr.ss_family)
		info(" Remote IP : %s\n", addr_to_str((struct sockaddr *)&config.dst_addr));

	info(" Port : %lu\n", config.port);
	info(" Block size : %u\n", config.block_size);
	info(" Number of blocks : %u\n", config.nb);
	info(" Interleave : %u\n", config.interleave);
	info(" Signature type : %s\n", config.sig->name);
	info(" Corrupt data : %d\n", config.corrupt_data);
	info(" Corrupt app_tag : %d\n", config.corrupt_app_tag);
	info(" Corrupt ref_tag : %d\n", config.corrupt_ref_tag);
	info(" Corrupt offset : %d\n", config.corrupt_offset);
	info(" ----------------------------------------------\n\n");
}

static void usage(const char *argv0)
{
	info("Usage:\n");
	info(" %s                   start a server and wait for connection\n", argv0);
	info(" %s                   <host> connect to server at <host>\n", argv0);
	info("\n");
	info("Options:\n");
	info(" -h, --help                   print this message\n");
	info(" -S, --src-addr <addr>        source IP or hostname\n");
	info(" -p, --port <port>            listen on/connect to port <port> (default 19875)\n");
	info(" -b, --block-size <size>      size of data block, only 512 and 4096 are supported (default 512)\n");
	info(" -n, --number-of-blocks <NB>  Number of blocks per RDMA operation (default 8)\n");
	info(" -o, --interleave             Data blocks and protection blocks are interleaved in the same buf\n");
	info(" -s, --sig-type <type>        Supported signature types: crc32, crc32c, t10dif-type1, t10dif-type2, "
					   "t10dif-type3 (default crc32)\n");
	info(" -c, --corrupt-data           Corrupt data (i.e., corrupt-offset = 0)  for READ read operation\n");
	info(" -a, --corrupt-app-tag        Corrupt apptag (i.e., corrupt-offset = block-size + 2) for READ "
					   "read operation (only for t10dif)\n");
	info(" -r, --corrupt-ref-tag        Corrupt reftag (i.e., corrupt-offset = block-size + 4) for READ "
					   "read operation (only for t10dif)\n");
	info(" -f, --corrupt-offset         Corrupt at specified linear offset (view in the wire domain) for "
					   "READ read operation\n");
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
	struct resources res;
	int rc = 1;

	/* parse the command line parameters */
	while (1) {
		int c;
		static struct option long_options[] = {
			{ .name = "help",		.has_arg = 0, .val = 'h' },
			{ .name = "src-addr",		.has_arg = 1, .val = 'S' },
			{ .name = "port",		.has_arg = 1, .val = 'p' },
			{ .name = "block-size",		.has_arg = 1, .val = 'b' },
			{ .name = "number-of-blocks",	.has_arg = 1, .val = 'n' },
			{ .name = "interleave",		.has_arg = 0, .val = 'o' },
			{ .name = "sig-type",		.has_arg = 1, .val = 's' },
			{ .name = "corrupt-data",	.has_arg = 0, .val = 'c' },
			{ .name = "corrupt-app-tag",	.has_arg = 0, .val = 'a' },
			{ .name = "corrupt-ref-tag",	.has_arg = 0, .val = 'r' },
			{ .name = "corrupt-offset",	.has_arg = 1, .val = 'f' },
			{ .name = NULL,			.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "hS:p:b:n:os:carf:", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'S':
			rc = get_sockaddr(optarg, (struct sockaddr *)&config.src_addr);
			if (rc) {
				err("invalid src-addr %s\n", optarg);
				usage(argv[0]);
				return -1;
			}
			break;
		case 'p':
			config.port = strtoul(optarg, NULL, 0);
			if (config.port == 0 || config.port > UINT16_MAX) {
				err("Invalid port %s\n", optarg);
				usage(argv[0]);
				return -1;
			}
			break;
		case 'b':
			config.block_size = strtoul(optarg, NULL, 0);
			if (config.block_size != 512 && config.block_size != 4096) {
				usage(argv[0]);
				return -1;
			}
			break;
		case 'n':
			config.nb = strtoul(optarg, NULL, 0);
			if (config.nb < 1) {
				usage(argv[0]);
				return -1;
			}
			break;
		case 'o':
			config.interleave = 1;
			break;
		case 's':
			config.sig = parse_sig_type(optarg);
			if (!config.sig) {
				usage(argv[0]);
				return -1;
			}
			break;
		case 'c':
			config.corrupt_data = 1;
			break;
		case 'a':
			config.corrupt_app_tag = 1;
			break;
		case 'r':
			config.corrupt_ref_tag = 1;
			break;
		case 'f':
			config.corrupt_offset = strtoul(optarg, NULL, 0);
			if (config.corrupt_offset < 0) {
				usage(argv[0]);
				return -1;
			}
			break;
		default:
			err("option -%c is not supported\n", c);
			return -1;
		}
	}

	/* parse the last parameter (if exists) as the server name */
	if (optind == argc - 1) {
		rc = get_sockaddr(argv[optind], (struct sockaddr *)&config.dst_addr);
		if (rc) {
			err("invalid dst-addr %s\n", optarg);
			return -1;
		}
	} else if (optind < argc) {
		err("too many arguments\n");
		return -1;
	}

	/* Use CRC32 by default */
	if (!config.sig)
		config.sig = &sig_ops[SIG_TYPE_CRC32];

	if ((config.corrupt_app_tag || config.corrupt_ref_tag) &&
	    strcmp("t10dif-type1", config.sig->name) &&
	    strcmp("t10dif-type2", config.sig->name) &&
	    strcmp("t10dif-type3", config.sig->name)) {
		err("The options --corrupt-app-tag and --corrupt-ref-tag are not supported for sig type %s\n",
			config.sig->name);
		return -1;
	}

	if (-1 == config.corrupt_offset) {
		if (config.corrupt_ref_tag)
			config.corrupt_offset = config.block_size + 4;
		else if (config.corrupt_app_tag)
			config.corrupt_offset = config.block_size + 2;
		else if (config.corrupt_data)
			config.corrupt_offset = 0;
	}

	print_config();

	resources_init(&res);

	if (rdma_create_id(NULL, &res.cm_id, NULL, RDMA_PS_TCP)) {
		err("rdma_create_id: %s\n", strerror(errno));
		return -1;
	}

	rc = cm_bind(&res);
	if (rc)
		goto free_res_and_exit;

	rc = resources_create(&res);
	if (rc) {
		if (skip)
			rc = 0;

		goto free_res_and_exit;
	}

	rc = cm_connect(&res);
	if (rc)
		goto free_res_and_exit;

	if (is_client())
		rc = client(&res);
	else
		rc = server(&res);

	if (rc)
		goto free_res_and_exit;

	rc = cm_disconnect(&res);
	if (rc)
		goto free_res_and_exit;

free_res_and_exit:
	if (resources_destroy(&res))
		rc = -1;

	return rc;
}
