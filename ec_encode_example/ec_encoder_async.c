/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
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
#include <pthread.h>

struct encoder_context {
    struct ibv_context      *context;
    struct ibv_pd           *pd;
    struct async_ec_context *ec_ctx;
    int                      infd;
    int                      outfd_sw;
    int                      outfd_off;
};

struct encoder_thread {
    pthread_t                thread;
    int                      index;
    struct inargs            *in;
};

pthread_mutex_t ctx_lock;

static void
ec_done(struct ibv_exp_ec_comp *ib_comp)
{
    struct ec_comp *comp = (void *)ib_comp - offsetof(struct ec_comp, comp);
    struct async_ec_context *ec_ctx = comp->ctx;
    int bytes;

    bytes = write(comp->out_fd,
                  comp->code.buf,
                  ec_ctx->block_size * ec_ctx->attr.m);
    if (bytes < (int)ec_ctx->block_size * ec_ctx->attr.m) {
        err_log("Failed write to fd1 (%d)\n", bytes);
        /*FIXME: fail app */
    }

    memset(comp->data.buf, 0, ec_ctx->block_size * ec_ctx->attr.k);
    memset(comp->code.buf, 0, ec_ctx->block_size * ec_ctx->attr.m);
    put_ec_comp(ec_ctx, comp);

    if (!ec_ctx->attr.polling)
        sem_post(&ec_ctx->sem);
    else
        ec_ctx->inflights--;
}

static void
close_io_files(struct encoder_context *ctx)
{
    close(ctx->outfd_sw);
    close(ctx->outfd_off);
    close(ctx->infd);
}

static int
open_io_files(struct encoder_context *ctx, struct encoder_thread *thread)
{
    char *outfile;
    struct inargs *in = thread->in;
    size_t max_filename;
    int err = 0;

    ctx->infd = open(in->datafile, O_RDONLY);
    if (ctx->infd < 0) {
        err_log("Failed to open file\n");
        return -EIO;
    }

    max_filename = strlen(in->datafile) + strlen(".code.offload") + 16;
    outfile = calloc(1, max_filename);
    if (!outfile) {
        err_log("Failed to alloc outfile\n");
        err = -ENOMEM;
        goto close_infd;
    }

    snprintf(outfile, max_filename, "%s.code.offload.%d", in->datafile, thread->index);
    unlink(outfile);
    ctx->outfd_off = open(outfile, O_RDWR | O_CREAT, 0666);
    if (ctx->outfd_off < 0) {
        err_log("Failed to open offload code file");
        free(outfile);
        err = -EIO;
        goto close_infd;
    }

    snprintf(outfile, max_filename, "%s.code.sw.%d", in->datafile, thread->index);
    unlink(outfile);
    ctx->outfd_sw = open(outfile, O_RDWR | O_CREAT, 0666);
    if (ctx->outfd_sw < 0) {
        err_log("Failed to open sw code file");
        free(outfile);
        err = -EIO;
        goto close_infd;
    }
    free(outfile);

    return 0;

close_infd:
    close(ctx->infd);

    return err;
}

static struct encoder_context *
init_ctx(struct ibv_device *ib_dev, struct encoder_thread *thread)
{
    struct encoder_context *ctx;
    struct inargs *in = thread->in;
    int err, i;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        err_log("Failed to allocate encoder context\n");
        return NULL;
    }

    ctx->context = ibv_open_device(ib_dev);
    if (!ctx->context) {
        err_log("Couldn't get context for %s\n",
            ibv_get_device_name(ib_dev));
        goto free_ctx;
    }

    ctx->pd = ibv_alloc_pd(ctx->context);
    if (!ctx->pd) {
        err_log("Failed to allocate PD\n");
        goto close_device;
    }

    ctx->ec_ctx = alloc_async_ec_ctx(ctx->pd, in->frame_size,
                                     in->k, in->m, in->w, in->aff,
                                     in->max_inflight_calcs,
                                     in->polling, in->in_memory, NULL);
    if (!ctx->ec_ctx) {
        err_log("Failed to allocate EC context\n");
        goto dealloc_pd;
    }

    for(i = 0 ; i < in->max_inflight_calcs ; i++) {
        ctx->ec_ctx->comp[i].comp.done = ec_done;
    }

    err = open_io_files(ctx, thread);
    if (err)
        goto free_ec;

    return ctx;

free_ec:
    free_async_ec_ctx(ctx->ec_ctx);
dealloc_pd:
    ibv_dealloc_pd(ctx->pd);
close_device:
    ibv_close_device(ctx->context);
free_ctx:
    free(ctx);

    return NULL;
}

static void
close_ctx(struct encoder_context *ctx)
{
    free_async_ec_ctx(ctx->ec_ctx);
    ibv_dealloc_pd(ctx->pd);

    if (ibv_close_device(ctx->context))
        err_log("Couldn't release context\n");


    close_io_files(ctx);
    free(ctx);
}

static void
usage(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s            start EC encoder\n", argv0);
    printf("\n");
    printf("Options:\n");
    printf("  -i, --ib-dev=<dev>          use IB device <dev> (default first device found)\n");
    printf("  -k, --data_blocks=<blocks>  Number of data blocks\n");
    printf("  -m, --code_blocks=<blocks>  Number of code blocks\n");
    printf("  -w, --gf=<gf>               Galois field GF(2^w)\n");
    printf("  -D, --datafile=<name>       Name of input file to encode\n");
    printf("  -s, --frame_size=<size>     size of EC frame\n");
    printf("  -r, --duration=<duration>   duration in seconds\n");
    printf("  -l, --calcs=<num inflights> num inflights for async calculations\n");
    printf("  -t, --threads=<num threads> number of parallel threads\n");
    printf("  -p, --polling               use polling mode\n");
    printf("  -d, --debug                 print debug messages\n");
    printf("  -v, --verbose               add verbosity\n");
    printf("  -h, --help                  display this output\n");
}

static int
process_inargs(int argc, char *argv[], struct inargs *in)
{
    int err;
    struct option long_options[] = {
        { .name = "ib-dev",        .has_arg = 1, .val = 'i' },
        { .name = "datafile",      .has_arg = 1, .val = 'D' },
        { .name = "frame_size",    .has_arg = 1, .val = 's' },
        { .name = "calcs",         .has_arg = 1, .val = 'l' },
        { .name = "data_blocks",   .has_arg = 1, .val = 'k' },
        { .name = "code_blocks",   .has_arg = 1, .val = 'm' },
        { .name = "duration",      .has_arg = 1, .val = 'r' },
        { .name = "gf",            .has_arg = 1, .val = 'w' },
        { .name = "affinity",      .has_arg = 1, .val = 'f' },
        { .name = "threads",       .has_arg = 1, .val = 't' },
        { .name = "polling",       .has_arg = 0, .val = 'p' },
        { .name = "debug",         .has_arg = 0, .val = 'd' },
        { .name = "verbose",       .has_arg = 0, .val = 'v' },
        { .name = "help",          .has_arg = 0, .val = 'h' },
        { 0 }
    };

    err = common_process_inargs(argc, argv, "i:D:s:l:k:m:w:r:f:t:phdv",
                    long_options, in, usage);
    if (err)
        return err;

    if (in->datafile == NULL) {
        err_log("No input datafile was given\n");
        return -EINVAL;
    }

    if (in->frame_size <= 0) {
        err_log("No frame_size given %d\n", in->frame_size);
        return -EINVAL;
    }

    return 0;
}

static int
encode_file(struct encoder_context *ctx)
{
    struct async_ec_context *ec_ctx = ctx->ec_ctx;
    int bytes, err = 0, sem_val;
    struct ec_comp *comp;

    /* Offload Computation */
    while (1) {
        if (!ec_ctx->attr.polling)
            sem_wait(&ec_ctx->sem);
        else if (ec_ctx->attr.max_inflight_calcs <= ec_ctx->inflights) {
            info_log("going to POLL completions.\n");
            goto do_poll;
        }

        comp = get_ec_comp(ec_ctx);
        comp->out_fd = ctx->outfd_off;

        bytes = read(ctx->infd,
                     comp->data.buf,
                     ec_ctx->block_size * ec_ctx->attr.k);
        if (bytes <= 0) {
            put_ec_comp(ec_ctx, comp);
            if (!ec_ctx->attr.polling)
                sem_post(&ec_ctx->sem);
            break;
        }

        err = ibv_exp_ec_encode_async(ec_ctx->calc, &comp->mem, &comp->comp);
        if (err) {
            err_log("Failed ibv_exp_ec_encode (%d)\n", err);
            goto put_comp;
        } else if (ec_ctx->attr.polling) {
            ec_ctx->inflights++;
        }
do_poll:
        if (ec_ctx->attr.polling)
            ibv_exp_ec_poll(ec_ctx->calc, ec_ctx->attr.max_inflight_calcs);
    }

    if (ec_ctx->attr.polling) {
        while (ec_ctx->inflights)
            ibv_exp_ec_poll(ec_ctx->calc, ec_ctx->attr.max_inflight_calcs);
    } else {
        sem_getvalue(&ec_ctx->sem, &sem_val);
        while(sem_val != (int)ec_ctx->attr.max_inflight_calcs) {
            sleep(1);
            sem_getvalue(&ec_ctx->sem, &sem_val);
        }
    }

    info_log("EC offload computation finished.\n");
    /* SW Computation */
    lseek(ctx->infd, 0, SEEK_SET);

    err = alloc_jerasure_buf_comp(comp);
    if (err)
        goto put_comp;

    while (1) {
        bytes = read(ctx->infd,
                     comp->data.buf,
                     ec_ctx->block_size * ec_ctx->attr.k);
        if (bytes <= 0)
            goto put_comp;

        err = ec_gold_encode(ec_ctx->encode_matrix, ec_ctx->attr.encode_matrix,
                             ec_ctx->attr.k, ec_ctx->attr.m, ec_ctx->attr.w,
                             comp->data.buf, comp->code.buf, ec_ctx->block_size,
                             comp->jerasure_src, comp->jerasure_dst);

        if (err) {
            err_log("Failed ec_gold_encode (%d)\n", err);
            goto free_jerasure_buf;
        }

        bytes = write(ctx->outfd_sw,
                      comp->code.buf,
                      ec_ctx->block_size * ec_ctx->attr.m);
        if (bytes < (int)ec_ctx->block_size * ec_ctx->attr.m) {
            err_log("Failed write to fd2 (%d)\n", err);
            goto free_jerasure_buf;
        }

        memset(comp->data.buf, 0, ec_ctx->block_size * ec_ctx->attr.k);
        memset(comp->code.buf, 0, ec_ctx->block_size * ec_ctx->attr.m);
    }

free_jerasure_buf:
    free_jerasure_buf_comp(comp);
put_comp:
    put_ec_comp(ec_ctx, comp);
    return err;
}

void * encoder_thread(void *arg)
{
    struct encoder_context *ctx;
    struct ibv_device *device;
    struct encoder_thread *thread = arg;
    int err;

    device = find_device(thread->in->devname);
    if (!device)
        return NULL;

    pthread_mutex_lock(&ctx_lock);
    ctx = init_ctx(device, thread);
    if (!ctx) {
        pthread_mutex_unlock(&ctx_lock);
        return NULL;
    }
    pthread_mutex_unlock(&ctx_lock);

    err = encode_file(ctx);
    if (err)
        err_log("failed to encode file %s\n", thread->in->datafile);

    close_ctx(ctx);
    return NULL;
}

int main(int argc, char *argv[])
{
    struct inargs in;
    struct encoder_thread *threads;
    int err;
    int i;

    err = process_inargs(argc, argv, &in);
    if (err)
        return err;

    if (0 != (err = pthread_mutex_init(&ctx_lock, NULL))) {
        err_log("Failed to create mutex, errno %d\n", err);
	return err;
    }

    threads = malloc(in.threads * sizeof(*threads));
    if (!threads) {
        err_log("Failed to allocate threads\n");
	return -ENOMEM;
    }

    for (i = 0; i < in.threads; ++i) {
        threads[i].index = i;
        threads[i].in = &in;
        if (0 != (err = pthread_create(&threads[i].thread, NULL, encoder_thread, &threads[i]))) {
		err_log("Failed to start thread, errno %d\n", err);
		goto free_threads;
	}
    }

    for (i = 0; i < in.threads; ++i) {
        if (0 != (err = pthread_join(threads[i].thread, NULL))) {
		err_log("Failed to join thread, errno %d\n", err);
		goto free_threads;
	}
    }

 free_threads:
    free(threads);
    pthread_mutex_destroy(&ctx_lock);
    return err;
}
