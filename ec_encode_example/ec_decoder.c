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

struct decoder_context {
    struct ibv_context  *context;
    struct ibv_pd       *pd;
    struct ec_context   *ec_ctx;
    int                 datafd;
    int                 codefd;
    int                 outfd;
};

static void
close_io_files(struct decoder_context *ctx)
{
    fsync(ctx->outfd);
    close(ctx->outfd);

    fsync(ctx->codefd);
    close(ctx->codefd);

    close(ctx->datafd);
}

static int
open_io_files(struct inargs *in, struct decoder_context *ctx)
{
    char *outfile;
    int err = 0;

    ctx->datafd = open(in->datafile, O_RDONLY);
    if (ctx->datafd < 0) {
        err_log("Failed to open data file\n");
        return -EIO;
    }

    ctx->codefd = open(in->codefile, O_RDONLY);
    if (ctx->codefd < 0) {
        err_log("Failed to open code file");
        err = -EIO;
        goto err_datafd;
    }

    outfile = calloc(1, strlen(in->datafile) + strlen(".decode") + 1);
    if (!outfile) {
        err_log("Failed to alloc outfile\n");
        err = -ENOMEM;
        goto err_codefd;
    }

    outfile = strcat(outfile, in->datafile);
    outfile = strcat(outfile, ".decode");
    unlink(outfile);
    ctx->outfd = open(outfile, O_RDWR | O_CREAT, 0666);
    if (ctx->outfd < 0) {
        err_log("Failed to open offload file");
        free(outfile);
        err = -EIO;
        goto err_codefd;
    }
    free(outfile);

    return 0;

err_codefd:
    close(ctx->codefd);
err_datafd:
    close(ctx->datafd);

    return err;
}

static struct decoder_context *
init_ctx(struct ibv_device *ib_dev,
     struct inargs *in)
{
    struct decoder_context *ctx;
    int err;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "Failed to allocate EC context\n");
        return NULL;
    }

    ctx->context = ibv_open_device(ib_dev);
    if (!ctx->context) {
        fprintf(stderr, "Couldn't get context for %s\n",
            ibv_get_device_name(ib_dev));
        goto free_ctx;
    }

    ctx->pd = ibv_alloc_pd(ctx->context);
    if (!ctx->pd) {
        fprintf(stderr, "Failed to allocate PD\n");
        goto close_device;
    }

    ctx->ec_ctx = alloc_ec_ctx(ctx->pd, in->frame_size,
                   in->k, in->m, in->w, 0, 1, in->failed_blocks, NULL, NULL);
    if (!ctx->ec_ctx) {
        fprintf(stderr, "Failed to allocate EC context\n");
        goto dealloc_pd;
    }

    err = open_io_files(in, ctx);
    if (err)
        goto free_ec;

    return ctx;

free_ec:
    free_ec_ctx(ctx->ec_ctx);
dealloc_pd:
    ibv_dealloc_pd(ctx->pd);
close_device:
    ibv_close_device(ctx->context);
free_ctx:
    free(ctx);

    return NULL;
}

static void
close_ctx(struct decoder_context *ctx)
{
    free_ec_ctx(ctx->ec_ctx);
    ibv_dealloc_pd(ctx->pd);

    if (ibv_close_device(ctx->context))
        fprintf(stderr, "Couldn't release context\n");


    close_io_files(ctx);
    free(ctx);
}

static void
usage(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s            start EC decoder\n", argv0);
    printf("\n");
    printf("Options:\n");
    printf("  -i, --ib-dev=<dev>         use IB device <dev> (default first device found)\n");
    printf("  -k, --data_blocks=<blocks> Number of data blocks\n");
    printf("  -m, --code_blocks=<blocks> Number of code blocks\n");
    printf("  -w, --gf=<gf>              Galois field GF(2^w)\n");
    printf("  -D, --datafile=<name>      Name of input data file\n");
    printf("  -C, --codefile=<name>      Name of input code file\n");
    printf("  -E, --erasures=<erasures>  Comma saparated failed blocks\n");
    printf("  -s, --frame_size=<size>    size of EC frame\n");
    printf("  -d, --debug                print debug messages\n");
    printf("  -v, --verbose              add verbosity\n");
    printf("  -h, --help                 display this output\n");
}

static int
process_inargs(int argc, char *argv[], struct inargs *in)
{
    int err;
    struct option long_options[] = {
        { .name = "ib-dev",        .has_arg = 1, .val = 'i' },
        { .name = "datafile",      .has_arg = 1, .val = 'D' },
        { .name = "codefile",      .has_arg = 1, .val = 'C' },
        { .name = "erasures",      .has_arg = 1, .val = 'E' },
        { .name = "frame_size",    .has_arg = 1, .val = 's' },
        { .name = "data_blocks",   .has_arg = 1, .val = 'k' },
        { .name = "code_blocks",   .has_arg = 1, .val = 'm' },
        { .name = "gf",            .has_arg = 1, .val = 'w' },
        { .name = "debug",         .has_arg = 0, .val = 'd' },
        { .name = "verbose",       .has_arg = 0, .val = 'v' },
        { .name = "help",          .has_arg = 0, .val = 'h' },
        { 0 }
    };

    err = common_process_inargs(argc, argv, "i:D:C:E:s:k:m:w:hdv",
                    long_options, in, usage);
    if (err)
        return err;

    if (in->datafile == NULL) {
        fprintf(stderr, "No input data file was given\n");
        return -EINVAL;
    }

    if (in->codefile == NULL) {
        fprintf(stderr, "No input code file was given\n");
        return -EINVAL;
    }

    if (in->frame_size <= 0) {
        fprintf(stderr, "No frame_size given %d\n", in->frame_size);
        return -EINVAL;
    }

    return 0;
}

static void
zero_erasures(struct ec_context *ctx, void *buf)
{
    int i;

    for (i = 0; i < ctx->attr.k; i++)
        if (ctx->erasures[i])
            memset(buf + i * ctx->block_size, 0, ctx->block_size);
}

static int
decode_file(struct decoder_context *ctx)
{
    struct ec_context *ec_ctx = ctx->ec_ctx;
    int dbytes, cbytes, wbytes;
    int err;

    while (1) {
        dbytes = read(ctx->datafd, ec_ctx->data.buf,
                  ec_ctx->block_size * ec_ctx->attr.k);
        if (dbytes <= 0)
            break;

        zero_erasures(ec_ctx, ec_ctx->data.buf);

        cbytes = read(ctx->codefd, ec_ctx->code.buf,
                  ec_ctx->block_size * ec_ctx->attr.m);
        if (cbytes <= 0)
            break;

        err = ibv_exp_ec_decode_sync(ec_ctx->calc, &ec_ctx->mem,
                                     ec_ctx->erasures, ec_ctx->de_mat);
        if (err) {
            fprintf(stderr, "Failed ibv_exp_ec_decode (%d)\n", err);
            return err;
        }

        wbytes = write(ctx->outfd, ec_ctx->data.buf, dbytes);
        if (wbytes < dbytes) {
            fprintf(stderr, "Failed write to fd (%d)\n", err);
            return err;
        }

        memset(ec_ctx->data.buf, 0, ec_ctx->block_size * ec_ctx->attr.k);
        memset(ec_ctx->code.buf, 0, ec_ctx->block_size * ec_ctx->attr.m);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct decoder_context *ctx;
    struct ibv_device *device;
    struct inargs in;
    int err;

    err = process_inargs(argc, argv, &in);
    if (err)
        return err;

    device = find_device(in.devname);
    if (!device)
        return -EINVAL;

    ctx = init_ctx(device, &in);
    if (!ctx)
        return -ENOMEM;

    err = decode_file(ctx);
    if (err)
        fprintf(stderr, "failed to encode file %s\n", in.datafile);

    close_ctx(ctx);

    return 0;
}
