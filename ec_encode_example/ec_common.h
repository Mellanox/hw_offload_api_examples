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

#ifndef EC_COMMON_H
#define EC_COMMON_H

#include "common.h"
#include <sys/queue.h>
#include <semaphore.h>
#include <infiniband/verbs_exp.h>
#include <jerasure.h>
#include <jerasure/reed_sol.h>
#include <gf_complete.h>



struct ec_context;
struct async_ec_context;

struct ec_mr {
    uint8_t              *buf;
    struct ibv_mr        *mr;
    struct ibv_sge       *sge;
};

struct ec_comp {
    struct ibv_exp_ec_comp   comp;
    struct ibv_exp_ec_mem    mem;
    struct ibv_exp_ec_mem    umem;
    struct ec_mr             data;
    struct ec_mr             code;
    struct ec_mr             udata;
    unsigned long long       bytes;
    struct async_ec_context  *ctx;
    int                      index;
    int                      out_fd;
    char                     **jerasure_src;
    char                     **jerasure_dst;
    SLIST_ENTRY(ec_comp)     entry;
};

struct async_ec_context {
    struct ibv_context               *context;
    struct ibv_pd                    *pd;
    struct ibv_exp_ec_calc           *calc;
    struct ibv_exp_ec_calc_init_attr attr;
    int                              block_size;
    uint32_t                         inflights;
    sem_t                            sem;
    pthread_spinlock_t               lock;
    SLIST_HEAD(, ec_comp)            comps_list;
    struct ec_comp                   *comp;
    uint8_t                          *en_mat;
    uint8_t                          *de_mat;
    int                              *encode_matrix;
// TODO: need to update for encode/decode/update async tests
/*
    int                *erasures_arr;
    uint32_t            erasures;
    int                *survived_arr;
    uint32_t            survived;
*/
    int                              num_data_updates;
    int                              num_code_updates;
    int                              in_memory;
};

struct ec_context {
    struct ibv_context               *context;
    struct ibv_pd                    *pd;
    struct ibv_exp_ec_calc           *calc;
    struct ibv_exp_ec_calc_init_attr attr;
    int                              block_size;
    struct ec_mr                     data;
    struct ec_mr                     code;
    struct ec_mr                     udata;
    struct ibv_exp_ec_mem            mem;
    struct ibv_exp_ec_mem            umem;
    uint8_t                          *en_mat;
    uint8_t                          *de_mat;
    int                              *encode_matrix;
    int                              *erasures_arr;
    uint8_t                          *data_updates_arr;
    uint8_t                          *code_updates_arr;
    uint8_t                          *erasures;
    int                              *survived_arr;
    uint8_t                          *survived;
    int                              num_data_updates;
    int                              num_code_updates;
    char                             **jerasure_src;
    char                             **jerasure_dst;
};

//void free_encode_matrix(struct ec_context *ctx);
//int alloc_encode_matrix(struct ec_context *ctx);
int extract_erasures(char *failed_blocks, int k, int m,
                     int *erasures_arr, uint8_t *erasures,
                     int *survived_arr, uint8_t *survived);
void free_decode_matrix(struct ec_context *ctx);
uint8_t* alloc_decode_matrix(int *encode_matrix, int k, int w, int *erasures_arr, int *survived_arr);
struct async_ec_context * alloc_async_ec_ctx(struct ibv_pd *pd, int frame_size,
                                 int k, int m, int w, int affinity,
                                 int max_inflight_calcs,
                                 int polling,
                                 int in_memory,
                                 char *failed_blocks);
void free_async_ec_ctx(struct async_ec_context *ctx);
struct ec_context * alloc_ec_ctx(struct ibv_pd *pd, int frame_size,
                                 int k, int m, int w, int affinity,
                                 int max_inflight_calcs,
                                 char *failed_blocks,
                                 char *data_updates,
                                 char *code_updates);
void free_ec_ctx(struct ec_context *ctx);
int sw_ec_encode(uint8_t *data, uint8_t *code, uint8_t *matrix, int block_size, int k, int m);
int jerasure_encode(uint8_t *data, uint8_t *code, int *matrix,
                    int block_size, int k, int m, int w);
void close_ec_ctx(struct ec_context *ctx);
void print_matrix_int(int *m, int rows, int cols);
void print_matrix_u8(uint8_t *m, int rows, int cols);
struct ibv_device *find_device(const char *devname);
void put_ec_comp(struct async_ec_context *ec_ctx, struct ec_comp *comp);
struct ec_comp *get_ec_comp(struct async_ec_context *ec_ctx);
int ec_gold_encode(int *encode_matrix, uint8_t *enc_matrix,
                   int k, int m, int w,
                   uint8_t *data, uint8_t *code, int block_size,
                   char **jerasure_src, char **jerasure_dst);
int alloc_jerasure_buf_comp(struct ec_comp *comp);
void free_jerasure_buf_comp(struct ec_comp *comp);

#endif /* EC_COMMON_H */
