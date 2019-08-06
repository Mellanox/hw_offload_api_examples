/*
 * Copyright (c) 2015 Mellanox Technologies.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "ec_common.h"

void print_matrix_u8(uint8_t *m, int rows, int cols)
{
    int i, j;

    for (i = 0; i < rows; i++) {
        for (j = 0; j < cols; j++) {
            if (j != 0)
                info_log(" ");

            info_log("%#x  ", m[i*cols+j]);
        }
        info_log("\n");
    }
}

void print_matrix_int(int *m, int rows, int cols)
{
    int i, j;

    for (i = 0; i < rows; i++) {
        for (j = 0; j < cols; j++) {
            if (j != 0)
                info_log(" ");

            info_log("%#x  ", m[i*cols+j]);
        }
        info_log("\n");
    }
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
        err_log("Failed to allocate encode matrix\n");
        return -ENOMEM;
    }

    rs_mat = reed_sol_vandermonde_coding_matrix(k, m, w);
    if (!rs_mat) {
        err_log("failed to allocate reed sol matrix\n");
        return -EINVAL;
    }

    for (i = 0; i < m; i++)
        for (j = 0; j < k; j++)
            matrix[j*m+i] = (uint8_t)rs_mat[i*k+j];
    print_matrix_u8(matrix, k, m);

    *en_mat = matrix;
    *encode_matrix = rs_mat;

    return 0;
}

int extract_bitmap(char *src, uint8_t *dst, int size)
{
    char *pt;
    int i = 0, num_updates = 0;

    pt = strtok (src, ",");

    while (pt != NULL && i < size) {
        if (pt[0] == '1') {
            num_updates++;
            dst[i] = 1;
        }
        pt = strtok (NULL, ",");
        i++;
    }

    if (i != size) {
        err_log("Expected %d blocks, but got %d\n", size, i);
        return -EINVAL;
    }

    if (num_updates == 0) {
        err_log("Asked to update 0 blocks. Nothing to do\n");
        return -EINVAL;
    }

    return num_updates;
}

int alloc_erasures(struct ec_context *ctx)
{
    int i;

    ctx->erasures_arr = calloc(ctx->attr.k + ctx->attr.m, sizeof(int));
    if (!ctx->erasures_arr) {
        err_log("failed to allocated erasures_arr buffer\n");
        return -ENOMEM;
    }

    ctx->erasures = calloc(ctx->attr.k + ctx->attr.m, sizeof(uint8_t));
    if (!ctx->erasures) {
        err_log("failed to allocated erasures buffer\n");
        goto err_erasures_arr;
    }

    ctx->survived_arr = calloc(ctx->attr.k + ctx->attr.m, sizeof(int));
    if (!ctx->survived_arr) {
        err_log("failed to allocated survived_arr buffer\n");
        goto err_erasures;
    }

    ctx->survived = calloc(ctx->attr.k + ctx->attr.m, sizeof(uint8_t));
    if (!ctx->survived) {
        err_log("failed to allocated survived buffer\n");
        goto err_survived_arr;
    }

    /* All survived by default */
    for (i = 0; i < ctx->attr.k + ctx->attr.m; ++i) {
        ctx->survived_arr[i] = 1;
        ctx->survived[i] = 1;
    }

    return 0;

err_survived_arr:
    free(ctx->survived_arr);
err_erasures:
    free(ctx->erasures);
err_erasures_arr:
    free(ctx->erasures_arr);

    return -ENOMEM;
}

void free_erasures(struct ec_context *ctx)
{
    free(ctx->survived);
    free(ctx->survived_arr);
    free(ctx->erasures);
    free(ctx->erasures_arr);
}

int extract_erasures(char *failed_blocks, int k, int m,
                     int *erasures_arr, uint8_t *erasures,
                     int *survived_arr, uint8_t *survived)
{
    char *pt;
    int i = 0, tot = 0;

    pt = strtok (failed_blocks, ",");
    while (pt != NULL) {
        if (i >= k + m) {
            err_log("too many data nodes blocks given %d\n", i);
            return -EINVAL;
        }

        if (pt[0] == '1') {
            survived_arr[i] = 0;
            survived[i] = 0;
            erasures_arr[i] = 1;
            erasures[i] = 1;
            if (++tot > m) {
                err_log("too much erasures %d\n", tot);
                return -EINVAL;

            }
        }
        pt = strtok (NULL, ",");
        i++;
    }

    if (tot == 0) {
        err_log("No erasures specified\n");
        return -EINVAL;
    }

    info_log("erasures:\n");
    for (i = 0; i < k + m; i++) {
        info_log("[%d]: Jerasure=%d Verbs=%u\n", i, erasures_arr[i], erasures[i]);
    }

    info_log("survived:\n");
    for (i = 0; i < k + m; i++) {
        info_log("[%d]: Jerasure=%d Verbs=%u\n", i, survived_arr[i], survived[i]);
    }

    return 0;
}

uint8_t* alloc_decode_matrix(int *encode_matrix, int k, int w,
                             int *erasures_arr, int *survived_arr)
{
    int *dec_mat;
    uint8_t *dematrix;
    int i, j, l = 0, m = 0;
    int err;

    for (i = 0; i < k; i++) {
        if (erasures_arr[i])
            m++;
    }

    dematrix = calloc(m * k, 1);
    if (!dematrix) {
        err_log("Failed to allocate decode matrix\n");
        return NULL;
    }

    dec_mat = calloc(k * k, sizeof(int));
    if (!dec_mat) {
        err_log("Failed to allocate dec_mat\n");
        goto err_demat;
    }

    err = jerasure_make_decoding_matrix(k, m, w, encode_matrix,
                        erasures_arr,
                        dec_mat, survived_arr);
    if (err) {
        err_log("failed making decoding matrix\n");
        goto err_decmat;
    }

    for (i = 0; i < k; i++) {
        if (erasures_arr[i]) {
            for (j = 0; j < k; j++)
                dematrix[j*m+l] = (uint8_t)dec_mat[i*k+j];
            l++;
        }
    }
    free(dec_mat);
    print_matrix_u8(dematrix, k, l);

    return dematrix;

err_decmat:
    free(dec_mat);
err_demat:
    free(dematrix);

    return NULL;
}

static int
ec_get_sg(struct ec_mr *data,
          struct ibv_pd *pd,
          int sge,
          int bs)
{
    int i;
    int size = sge * bs;

    data->buf = calloc(1, size);
    if (!data->buf) {
        err_log("Failed to allocate data buffer\n");
                return -ENOMEM;
        }

    data->mr = ibv_reg_mr(pd, data->buf, size, IBV_ACCESS_LOCAL_WRITE);
    if (!data->mr) {
        err_log("Failed to allocate data MR\n");
                goto free_buf;
    }

    data->sge = calloc(sge, sizeof(*data->sge));
    if (!data->sge) {
        err_log("Failed to allocate data sges\n");
        goto dereg_mr;
    }

    for (i = 0; i < sge; i++) {
        data->sge[i].lkey = data->mr->lkey;
        data->sge[i].addr = (uintptr_t)data->buf + i * bs;
        data->sge[i].length = bs;
    }

    return 0;

dereg_mr:
    ibv_dereg_mr(data->mr);
free_buf:
    free(data->buf);

    return -ENOMEM;
}

struct ec_comp *
get_ec_comp(struct async_ec_context *ec_ctx)
{
    struct ec_comp *comp;

    pthread_spin_lock(&ec_ctx->lock);
    comp = SLIST_FIRST(&ec_ctx->comps_list);
    SLIST_REMOVE(&ec_ctx->comps_list, comp, ec_comp, entry);
    pthread_spin_unlock(&ec_ctx->lock);

    return comp;
}

void put_ec_comp(struct async_ec_context *ec_ctx, struct ec_comp *comp)
{
    pthread_spin_lock(&ec_ctx->lock);
    SLIST_INSERT_HEAD(&ec_ctx->comps_list, comp, entry);
    pthread_spin_unlock(&ec_ctx->lock);
}

static void free_ec_mr(struct ec_mr *e_mr)
{
    free(e_mr->sge);
    ibv_dereg_mr(e_mr->mr);
    free(e_mr->buf);

}

static void free_comp_ec_mrs(struct ec_comp *comp)
{

    free_ec_mr(&comp->udata);
    free_ec_mr(&comp->code);
    free_ec_mr(&comp->data);
}

int alloc_jerasure_buf_comp(struct ec_comp *comp)
{
    struct async_ec_context *ctx = comp->ctx;
    int i;

    comp->jerasure_src = malloc(sizeof(char*) * ctx->attr.k);
    if (!comp->jerasure_src) {
        err_log("Failed to allocate jerasure data buffer\n");
        return -ENOMEM;
    }

    comp->jerasure_dst = malloc(sizeof(char*) * ctx->attr.m);
    if (!comp->jerasure_dst) {
        err_log("Failed to allocate jerasure code buffer\n");
        goto free_src;
    }

    for (i = 0; i < ctx->attr.k; i++)
        comp->jerasure_src[i] = (char*)&comp->data.buf[i * ctx->block_size];

    for (i = 0; i < ctx->attr.m; i++)
        comp->jerasure_dst[i] = (char*)&comp->code.buf[i * ctx->block_size];

    return 0;

free_src:
    free(comp->jerasure_src);
    return -ENOMEM;
}

void free_jerasure_buf_comp(struct ec_comp *comp)
{
    free(comp->jerasure_src);
    free(comp->jerasure_dst);
}

static int alloc_comp_ec_mrs(struct ec_comp *comp)
{
    struct async_ec_context *ctx = comp->ctx;
    int err;

    err = ec_get_sg(&comp->data, ctx->pd, ctx->attr.k, ctx->block_size);
    if (err)
        return err;

    err = ec_get_sg(&comp->code, ctx->pd, ctx->attr.m, ctx->block_size);
    if (err)
        goto free_dbuf;

    err = ec_get_sg(&comp->udata, ctx->pd,
        ctx->attr.m + 2 * ctx->num_data_updates,
        ctx->block_size);
    if (err)
        goto free_cbuf;

    comp->mem.data_blocks = comp->data.sge;
    comp->mem.num_data_sge = ctx->attr.k;
    comp->mem.code_blocks = comp->code.sge;
    comp->mem.num_code_sge = ctx->attr.m;
    comp->mem.block_size = ctx->block_size;

    comp->umem.data_blocks = comp->udata.sge;
    comp->umem.num_data_sge = ctx->num_code_updates + 2 * ctx->num_data_updates;
    comp->umem.code_blocks = comp->code.sge;
    comp->umem.num_code_sge = ctx->num_code_updates;
    comp->umem.block_size = ctx->block_size;


    return 0;

free_cbuf:
    free_ec_mr(&comp->code);
free_dbuf:
    free_ec_mr(&comp->data);

    return -ENOMEM;
}

static void
free_ec_mrs(struct ec_context *ctx)
{

    free_ec_mr(&ctx->udata);
    free_ec_mr(&ctx->code);
    free_ec_mr(&ctx->data);
}

static int
alloc_buf_for_jerasure(struct ec_context *ctx)
{
    int i, err = 0;

    if (ctx->attr.w != 8)
        return 0;

    ctx->jerasure_src = malloc(sizeof(char*) * ctx->attr.k);
    if (!ctx->jerasure_src) {
        err_log("Failed to allocate jerasure data buffer\n");
        return -ENOMEM;
    }
    ctx->jerasure_dst = malloc(sizeof(char*) * ctx->attr.m);
    if (!ctx->jerasure_dst) {
        err_log("Failed to allocate jerasure code buffer\n");
        err = -ENOMEM;
        goto free_src_buf;
    }

    for (i = 0; i < ctx->attr.k; i++)
        ctx->jerasure_src[i] = (char*)&ctx->data.buf[i * ctx->block_size];

    for (i = 0; i < ctx->attr.m; i++)
        ctx->jerasure_dst[i] = (char*)&ctx->code.buf[i * ctx->block_size];

    return err;

free_src_buf:
    free(ctx->jerasure_src);
    return err;
}

static int
alloc_ec_mrs(struct ec_context *ctx)
{
    int err;

    err = ec_get_sg(&ctx->data, ctx->pd, ctx->attr.k, ctx->block_size);
    if (err)
        return err;

    err = ec_get_sg(&ctx->code, ctx->pd, ctx->attr.m, ctx->block_size);
    if (err)
        goto free_dbuf;

    err = ec_get_sg(&ctx->udata, ctx->pd,
            ctx->attr.m + 2 * ctx->num_data_updates,
            ctx->block_size);
    if (err)
        goto free_cbuf;

    ctx->mem.data_blocks = ctx->data.sge;
    ctx->mem.num_data_sge = ctx->attr.k;
    ctx->mem.code_blocks = ctx->code.sge;
    ctx->mem.num_code_sge = ctx->attr.m;
    ctx->mem.block_size = ctx->block_size;

    ctx->umem.data_blocks = ctx->udata.sge;
    ctx->umem.num_data_sge = ctx->num_code_updates + 2 * ctx->num_data_updates;
    ctx->umem.code_blocks = ctx->code.sge;
    ctx->umem.num_code_sge = ctx->num_code_updates;
    ctx->umem.block_size = ctx->block_size;

    return 0;

free_cbuf:
    ibv_dereg_mr(ctx->code.mr);
    free(ctx->code.buf);
    free(ctx->code.sge);
free_dbuf:
    ibv_dereg_mr(ctx->data.mr);
    free(ctx->data.buf);
    free(ctx->data.sge);

    return err;
}

static void
copy_comp_mr(struct ec_comp* src_comp, struct ec_comp *dst_comp)
{
        dst_comp->data.mr = src_comp->data.mr;
        dst_comp->data.buf = src_comp->data.buf;
        dst_comp->data.sge = src_comp->data.sge;
        dst_comp->code.mr = src_comp->code.mr;
        dst_comp->code.buf = src_comp->code.buf;
        dst_comp->code.sge = src_comp->code.sge;
        dst_comp->udata.mr = src_comp->udata.mr;
        dst_comp->udata.buf = src_comp->udata.buf;
        dst_comp->udata.sge = src_comp->udata.sge;
        dst_comp->mem.data_blocks = src_comp->data.sge;
        dst_comp->mem.code_blocks = src_comp->code.sge;
        dst_comp->umem.data_blocks = src_comp->udata.sge;
        dst_comp->umem.code_blocks = src_comp->code.sge;
}

static void
fill_comp_ctx_data(struct ec_comp *comp, struct async_ec_context *ctx)
{
        comp->mem.num_data_sge = ctx->attr.k;
        comp->mem.num_code_sge = ctx->attr.m;
        comp->mem.block_size = ctx->block_size;
        comp->umem.num_data_sge = ctx->num_code_updates + 2 * ctx->num_data_updates;
        comp->umem.num_code_sge = ctx->num_code_updates;
        comp->umem.block_size = ctx->block_size;
}

struct async_ec_context *
alloc_async_ec_ctx(struct ibv_pd *pd, int frame_size,
                int k, int m, int w,
                int affinity,
                int max_inflight_calcs,
                int polling,
                int in_memory,
                char *failed_blocks)
{
    struct async_ec_context *ctx;
    struct ibv_exp_device_attr dattr;
    int err, i, j;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        err_log("Failed to allocate EC context\n");
        return NULL;
    }

    ctx->pd = pd;
    ctx->context = pd->context;

    memset(&dattr, 0, sizeof(dattr));
    dattr.comp_mask = IBV_EXP_DEVICE_ATTR_EXP_CAP_FLAGS |
                      IBV_EXP_DEVICE_ATTR_EC_CAPS |
                      IBV_EXP_DEVICE_ATTR_EC_GF_BASE;
    err = ibv_exp_query_device(ctx->context, &dattr);
    if (err) {
        err_log("Couldn't query device for EC offload caps.\n");
        goto free_ctx;
    }

    if (!(dattr.exp_device_cap_flags & IBV_EXP_DEVICE_EC_OFFLOAD)) {
        err_log("EC offload not supported by driver.\n");
        goto free_ctx;
    }

    if (!(dattr.ec_w_mask & (1<<(w-1)))) {
        err_log("W(%d) not supported for given device(%s)\n",
                 w, ctx->context->device->name);
        goto free_ctx;
    }

    info_log("EC offload supported by driver.\n");
    info_log("max_ec_calc_inflight_calcs %d\n", dattr.ec_caps.max_ec_calc_inflight_calcs);
    info_log("max_data_vector_count %d\n", dattr.ec_caps.max_ec_data_vector_count);

    ctx->attr.comp_mask = IBV_EXP_EC_CALC_ATTR_MAX_INFLIGHT |
            IBV_EXP_EC_CALC_ATTR_K |
            IBV_EXP_EC_CALC_ATTR_M |
            IBV_EXP_EC_CALC_ATTR_W |
            IBV_EXP_EC_CALC_ATTR_MAX_DATA_SGE |
            IBV_EXP_EC_CALC_ATTR_MAX_CODE_SGE |
            IBV_EXP_EC_CALC_ATTR_ENCODE_MAT |
            IBV_EXP_EC_CALC_ATTR_AFFINITY |
            IBV_EXP_EC_CALC_ATTR_POLLING;
    ctx->attr.max_inflight_calcs = max_inflight_calcs;
    ctx->attr.k = k;
    ctx->attr.m = m;
    ctx->attr.w = w;
    ctx->attr.max_data_sge = k;
    ctx->attr.max_code_sge = m;
    ctx->attr.affinity_hint = affinity;
    ctx->attr.polling = polling;
    ctx->block_size = align_any((frame_size + ctx->attr.k - 1) / ctx->attr.k, 64);
    ctx->comp = calloc(max_inflight_calcs, sizeof(*ctx->comp));
    if (!ctx->comp) {
        err_log("Failed to allocate EC context comps\n");
        goto free_ctx;
    }

    sem_init(&ctx->sem, 0, max_inflight_calcs);
    pthread_spin_init(&ctx->lock, PTHREAD_PROCESS_PRIVATE);
    SLIST_INIT(&ctx->comps_list);

    ctx->in_memory = in_memory;
    ctx->comp[0].index = 0;
    ctx->comp[0].ctx = ctx;
    err = alloc_comp_ec_mrs(&ctx->comp[0]);
    if (err)
        goto free_ctx;
    put_ec_comp(ctx, &ctx->comp[0]);

    for (i = 1 ; i < max_inflight_calcs ; i++) {
        ctx->comp[i].index = i;
        ctx->comp[i].ctx = ctx;
        if (!in_memory) {
            err = alloc_comp_ec_mrs(&ctx->comp[i]);
            if (err)
                goto free_mrs;
        } else {
            copy_comp_mr(&ctx->comp[0], &ctx->comp[i]);
            fill_comp_ctx_data(&ctx->comp[i], ctx);
        }
        put_ec_comp(ctx, &ctx->comp[i]);
    }

    err = alloc_encode_matrix(ctx->attr.k, ctx->attr.m, ctx->attr.w,
                  &ctx->en_mat, &ctx->encode_matrix);
    if (err)
        goto free_mrs;

    ctx->attr.encode_matrix = ctx->en_mat;

/* TODO: add support for async_decode
    if (failed_blocks) {
        if (extract_erasures(failed_blocks, ctx))
            goto free_mrs;

        err = alloc_decode_matrix(ctx);
        if (err)
            goto clean_encode_mat;
    }
*/
    ctx->calc = ibv_exp_alloc_ec_calc(ctx->pd, &ctx->attr);
    if (!ctx->calc) {
        err_log("Failed to allocate EC calc\n");
        goto clean_decode_mat;
    }

    return ctx;

clean_decode_mat:
    //free_decode_matrix(ctx);
clean_encode_mat:
    free_encode_matrix(ctx->en_mat);
free_mrs:
    free_comp_ec_mrs(&ctx->comp[0]);
    put_ec_comp(ctx, &ctx->comp[0]);
    for (j = 1 ; j < i ; j++) {
        if (!in_memory)
           free_comp_ec_mrs(&ctx->comp[j]);
        put_ec_comp(ctx, &ctx->comp[j]);
    }
free_ctx:
    free(ctx);

    return NULL;
}

void free_async_ec_ctx(struct async_ec_context *ctx)
{
    unsigned i;

    ibv_exp_dealloc_ec_calc(ctx->calc);
    free(ctx->encode_matrix);
    free(ctx->attr.encode_matrix);

    free_comp_ec_mrs(&ctx->comp[0]);
    put_ec_comp(ctx, &ctx->comp[0]);
    for (i = 1; i < ctx->attr.max_inflight_calcs; i++) {
        if (!ctx->in_memory)
            free_comp_ec_mrs(&ctx->comp[i]);
        put_ec_comp(ctx, &ctx->comp[i]);
    }

    //free(ctx->data_updates_arr);
    //free(ctx->code_updates_arr);
    free(ctx->comp);
    free(ctx);
}

void free_jerasure_bufs(struct ec_context *ctx)
{
    if (ctx->attr.w != 8)
        return;

    free(ctx->jerasure_src);
    free(ctx->jerasure_dst);
}

struct ec_context *
alloc_ec_ctx(struct ibv_pd *pd, int frame_size,
             int k, int m, int w, int affinity,
             int max_inflight_calcs,
             char *failed_blocks,
             char *data_updates,
             char *code_updates)
{
    struct ec_context *ctx;
    struct ibv_exp_device_attr dattr;
    int err;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        err_log("Failed to allocate EC context\n");
        return NULL;
    }

    ctx->pd = pd;
    ctx->context = pd->context;

    memset(&dattr, 0, sizeof(dattr));
    dattr.comp_mask = IBV_EXP_DEVICE_ATTR_EXP_CAP_FLAGS |
                      IBV_EXP_DEVICE_ATTR_EC_CAPS |
                      IBV_EXP_DEVICE_ATTR_EC_GF_BASE;
    err = ibv_exp_query_device(ctx->context, &dattr);
    if (err) {
        err_log("Couldn't query device for EC offload caps.\n");
        goto free_ctx;
    }

    if (!(dattr.exp_device_cap_flags & IBV_EXP_DEVICE_EC_OFFLOAD)) {
        err_log("EC offload not supported by driver.\n");
        goto free_ctx;
    }

    if (!(dattr.ec_w_mask & (1<<(w-1)))) {
        err_log("W(%d) not supported for given device(%s)\n",
                 w, ctx->context->device->name);
        goto free_ctx;
    }

    info_log("EC offload supported by driver.\n");
    info_log("max_ec_calc_inflight_calcs %d\n", dattr.ec_caps.max_ec_calc_inflight_calcs);
    info_log("max_data_vector_count %d\n", dattr.ec_caps.max_ec_data_vector_count);

    ctx->attr.comp_mask = IBV_EXP_EC_CALC_ATTR_MAX_INFLIGHT |
            IBV_EXP_EC_CALC_ATTR_K |
            IBV_EXP_EC_CALC_ATTR_M |
            IBV_EXP_EC_CALC_ATTR_W |
            IBV_EXP_EC_CALC_ATTR_MAX_DATA_SGE |
            IBV_EXP_EC_CALC_ATTR_MAX_CODE_SGE |
            IBV_EXP_EC_CALC_ATTR_ENCODE_MAT |
            IBV_EXP_EC_CALC_ATTR_AFFINITY |
            IBV_EXP_EC_CALC_ATTR_POLLING;
    ctx->attr.max_inflight_calcs = max_inflight_calcs;
    ctx->attr.k = k;
    ctx->attr.m = m;
    ctx->attr.w = w;
    ctx->attr.max_data_sge = k;
    ctx->attr.max_code_sge = m;
    ctx->attr.affinity_hint = affinity;
    ctx->block_size = align_any((frame_size + ctx->attr.k - 1) / ctx->attr.k, 64);

    if (data_updates) {
        ctx->data_updates_arr = calloc(ctx->attr.k, sizeof(uint8_t));
        if (!ctx->data_updates_arr) {
            err_log("failed to allocated data updates buffer\n");
            goto free_ctx;
        }
        ctx->num_data_updates = extract_bitmap(data_updates,
                               ctx->data_updates_arr,
                               ctx->attr.k);
        if (ctx->num_data_updates < 0) {
            err_log("Failed to extract data update blocks\n");
            goto free_data_updates;
        }

        if (ctx->attr.m + 2 * ctx->num_data_updates >= ctx->attr.k) {
            err_log("Update is harder then encode. "
                "Please use encode\n");
            goto free_data_updates;
        }
    }

    if (code_updates) {
        ctx->code_updates_arr = calloc(ctx->attr.m, sizeof(uint8_t));
        if (!ctx->code_updates_arr) {
            err_log("failed to allocated code updates buffer\n");
            goto free_data_updates;
        }
        ctx->num_code_updates = extract_bitmap(code_updates,
                               ctx->code_updates_arr,
                               ctx->attr.m);
        if (ctx->num_code_updates < 0) {
            err_log("Failed to extract code update blocks\n");
            goto free_code_updates;
        }
    }

    err = alloc_ec_mrs(ctx);
    if (err)
        goto free_code_updates;

    err = alloc_buf_for_jerasure(ctx);
    if (err)
        goto free_mrs;

    err = alloc_encode_matrix(ctx->attr.k, ctx->attr.m, ctx->attr.w,
                  &ctx->en_mat, &ctx->encode_matrix);
    if (err)
        goto free_jerasure_bufs;

    ctx->attr.encode_matrix = ctx->en_mat;

    if (failed_blocks) {
        if (alloc_erasures(ctx))
            goto clean_encode_mat;
        if (extract_erasures(failed_blocks, k, m,
                             ctx->erasures_arr, ctx->erasures,
                             ctx->survived_arr, ctx->survived))
            goto free_erasures;

        ctx->de_mat = alloc_decode_matrix(ctx->encode_matrix,
                                          k, w,
                                          ctx->erasures_arr,
                                          ctx->survived_arr);
        if (!ctx->de_mat)
            goto free_erasures;
    }

    ctx->calc = ibv_exp_alloc_ec_calc(ctx->pd, &ctx->attr);
    if (!ctx->calc) {
        err_log("Failed to allocate EC calc\n");
        goto clean_decode_mat;
    }

    return ctx;

clean_decode_mat:
    free(ctx->de_mat);
free_erasures:
    free_erasures(ctx);
clean_encode_mat:
    free_encode_matrix(ctx->en_mat);
free_jerasure_bufs:
    free_jerasure_bufs(ctx);
free_mrs:
    free_ec_mrs(ctx);
free_code_updates:
    free(ctx->code_updates_arr);
free_data_updates:
    free(ctx->data_updates_arr);
free_ctx:
    free(ctx);

    return NULL;
}

void free_ec_ctx(struct ec_context *ctx)
{
    ibv_exp_dealloc_ec_calc(ctx->calc);
    free(ctx->survived);
    free(ctx->survived_arr);
    free(ctx->erasures);
    free(ctx->erasures_arr);
    free(ctx->de_mat);
    free_ec_mrs(ctx);
    free_jerasure_bufs(ctx);
    free(ctx->encode_matrix);
    free(ctx->attr.encode_matrix);
    free(ctx->data_updates_arr);
    free(ctx->code_updates_arr);
    free(ctx);
}

#define LOG_TABLE 0, 1, 4, 2, 8, 5, 10, 3, 14, 9, 7, 6, 13, 11, 12
#define ILOG_TABLE 1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9

const uint8_t gf_w4_log[]={LOG_TABLE};
const uint8_t gf_w4_ilog[]={ILOG_TABLE};

uint8_t gf_w4_mul(uint8_t x, uint8_t y)
{
        int log_x, log_y, log_r;

        if (!x || !y)
                return 0;

        log_x = gf_w4_log[x - 1];
        log_y = gf_w4_log[y - 1];
        log_r = (log_x + log_y) % 15;

        return gf_w4_ilog[log_r];
}

uint8_t galois_w4_mult(uint8_t x, uint8_t y4)
{
        uint8_t r_h, r_l;

        r_h = gf_w4_mul(x >> 4, y4 & 0xf);
        r_l = gf_w4_mul(x & 0xf, y4 & 0xf);

        return (r_h << 4) | r_l;

}

int ec_gold_encode(int *encode_matrix, uint8_t *enc_matrix,
                   int k, int m, int w,
                   uint8_t *data, uint8_t *code, int block_size,
                   char **jerasure_src, char **jerasure_dst)
{
    int err = 0;

    if (w == 8)
        jerasure_matrix_encode(k, m, w,
                               encode_matrix,
                               jerasure_src,
                               jerasure_dst,
                               block_size);
    else
        err = sw_ec_encode(data, code,
                           enc_matrix,
                           block_size,
                           k, m);
    return err;
}

int sw_ec_encode(uint8_t *data, uint8_t *code, uint8_t *matrix,
                 int block_size, int k, int m)
{
    int  index, offset;
    int i, j;

    for (i = 0; i < block_size * k; i++) {
        index = i / block_size;
        offset = i % block_size;

        for (j = 0; j < m; j++)
            code[block_size * j + offset] ^=
            galois_w4_mult(data[i], matrix[index*m+j]);
    }

    return 0;
}

struct ibv_device *
find_device(const char *devname)
{
    struct ibv_device **dev_list = NULL;
    struct ibv_device *device = NULL;

    dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        err_log("Failed to get IB devices list");
        return NULL;
    }

    if (!devname) {
        device = *dev_list;
        if (!device)
            err_log("No IB devices found\n");
    } else {
        int i;

        for (i = 0; dev_list[i]; ++i)
            if (!strcmp(ibv_get_device_name(dev_list[i]),
                    devname))
                break;

        device = dev_list[i];
        if (!device)
            err_log("IB device %s not found\n", devname);
    }

    ibv_free_device_list(dev_list);

    return device;
}
