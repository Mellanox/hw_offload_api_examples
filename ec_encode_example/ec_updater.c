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

struct updater_context {
    struct ibv_context  *context;
    struct ibv_pd       *pd;
    struct ec_context   *ec_ctx;
    int                 datafd;
    int                 codefd;
};

static void
close_io_files(struct updater_context *ctx)
{
    fsync(ctx->codefd);
    close(ctx->codefd);

    fsync(ctx->datafd);
    close(ctx->datafd);
}

static int
open_io_files(struct inargs *in, struct updater_context *ctx)
{
    ctx->datafd = open(in->datafile, O_RDWR);
    if (ctx->datafd < 0) {
        err_log("Failed to open file\n");
        return -EIO;
    }
    ctx->codefd = open(in->codefile, O_RDWR);
    if (ctx->codefd < 0) {
        err_log("Failed to open code file");
        close(ctx->datafd);
        return -EIO;
    }

    return 0;
}

static struct updater_context *
init_ctx(struct ibv_device *ib_dev, struct inargs *in)
{
    struct updater_context *ctx;
    int err;

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

    ctx->ec_ctx = alloc_ec_ctx(ctx->pd, in->frame_size,
                   in->k, in->m, in->w, 0, 1, NULL,
                   in->data_updates, in->code_updates);
    if (!ctx->ec_ctx) {
        err_log("Failed to allocate EC context\n");
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
close_ctx(struct updater_context *ctx)
{
    free_ec_ctx(ctx->ec_ctx);
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
    printf("  -i, --ib-dev=<dev>         use IB device <dev> (default first device found)\n");
    printf("  -k, --dblocks=<blocks>     Number of data blocks\n");
    printf("  -m, --cblocks=<blocks>     Number of code blocks\n");
    printf("  -w, --gf=<gf>              Galois field GF(2^w)\n");
    printf("  -u, --data_updates=<update_data_blocks>  Comma saparated blocks to be updated\n");
    printf("  -c  --code_updates=<update_code_blocks>  Comma saparated blocks to be computed\n");
    printf("  -D, --datafile=<name>      Name of input file to update\n");
    printf("  -C, --codefile=<name>      Name of input file with code\n");
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
        { .name = "frame_size",    .has_arg = 1, .val = 's' },
        { .name = "dblocks",       .has_arg = 1, .val = 'k' },
        { .name = "cblocks",       .has_arg = 1, .val = 'm' },
        { .name = "data_updates",  .has_arg = 1, .val = 'u' },
        { .name = "code_updates",  .has_arg = 1, .val = 'c' },
        { .name = "gf",            .has_arg = 1, .val = 'w' },
        { .name = "debug",         .has_arg = 0, .val = 'd' },
        { .name = "verbose",       .has_arg = 0, .val = 'v' },
        { .name = "help",          .has_arg = 0, .val = 'h' },
        { 0 }
    };

    err = common_process_inargs(argc, argv, "i:I:D:C:u:c:s:k:m:w:hdv",
                    long_options, in, usage);
    if (err)
        return err;

    if (in->datafile == NULL) {
        err_log("No input datafile was given\n");
        return -EINVAL;
    }
    if (in->codefile == NULL) {
        err_log("No inpute code was given\n");
        return -EINVAL;
    }

    if (in->frame_size <= 0) {
        err_log("No frame_size given %d\n", in->frame_size);
        return -EINVAL;
    }

    return 0;
}

/*
 * Creates random string of given length.
 * Constraint: buffer is alocated.
 */
static void
rand_str(uint8_t *dest, size_t length) {
    char charset[] = "0123456789"
             "abcdefghijklmnopqrstuvwxyz"
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        size_t index;

    while (length-- > 0) {
        index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
}

/*
 * Focus on one stripe of data in given file from given position.
 * View data as divided into blocks.
 * Read blocks as described by pattern, i.e.
 * for pattern 0,1,0,1 - read block 1 and block 3.
 * Store them in a buffer as prescribed by step, i.e
 * with distance step * bs between blocks.
 *
 * Constraints:
 *  - buf is preallocated buffer
 *  - pattern is an array with at lease `blocks` elements
 *
 * Return: number of read bytes on success, errno on fail
 */
static int
read_by_pattern(int fd, int pos, int blocks, int bs,
        uint8_t *pattern, uint8_t *buf, int step)
{
    int i, err, rbytes, bytes = 0, curr = 0;

    for (i = 0; i < blocks; i++) {
        if (pattern[i]) {
        /* We should read block i */
            /* Move cursor to required position */
            err = lseek(fd, pos + i * bs, SEEK_SET);
            if (err < 0)
                return err;

            /* Read data block */
            rbytes = read(fd, buf + curr * (step + 1) * bs,
                      (size_t) bs);
            if (rbytes < 0)
                return rbytes;

            /* Summon bytes */
            bytes += rbytes;
            if (rbytes < bs)
                return bytes;

            /* We read another block */
            curr++;
        }
    }
    return bytes;
}

/*
 * View data as divided into blocks of given size.
 * Write blocks as described by pattern, i.e.
 * for pattern 0,1,0,1 - write block 1 and block 3
 * with distance step * bs between blocks.
 * Write to given file at given possition.
 * Stop writing once total_bytes reached.
 *
 * Constraints:
 * - pattern is an array with at lease `blocks` elements
 *
 * Return: 0 on success, errno on fail
 */
static int
write_by_pattern(int fd, int pos, int blocks, int bs, uint8_t *pattern,
                 uint8_t *buf, int step, int total_bytes)
{
    int left = total_bytes;
    int i, err,  wbytes, rbytes;
    int curr = 0;

    for (i = 0; i < blocks; i++) {
        if (pattern[i]) {
        /* Write to block i */
            /* Count bytes in current block */
            rbytes = left < bs ? left : bs;

            /* Set cursor */
            err = lseek(fd, pos + i * bs, SEEK_SET);
            if (err < 0)
                return err;

            /* Write to file */
            wbytes = write(fd, buf + curr * (step + 1) * bs,
                       (size_t) rbytes);
            if (wbytes < 0)
                return wbytes;

            if (wbytes < rbytes) {
                err_log("Expected to write %d bytes. Wrote %d bytes\n", bs, wbytes);
                return -EINVAL;
            }
            /* We wrote one more block */
            curr++;
            left -= bs;
            if (left < 0)
                break;
        }
    }
    return 0;
}

/*
 * Recompute requred redundancices
 * Constraints:
 * - assumes data entries in sg are filled.
 * Return: 0 - on success, errno on fail
 */
static int
compute_code(struct updater_context *ctx, int stripe,
             uint8_t *code_updates, int num_code_updates)
{
    struct ec_context *ec_ctx = ctx->ec_ctx;
    int m = ec_ctx->attr.m;
    int bs = ec_ctx->block_size;
    uint8_t *data_updates = ctx->ec_ctx->data_updates_arr;
    int rbytes, err;

    /* Read required code blocks */
    rbytes = read_by_pattern(ctx->codefd, stripe * m * bs, m, bs,
                 code_updates, ec_ctx->udata.buf, 0);
    if (rbytes < 0)
        return rbytes;
    if (rbytes < num_code_updates * bs) {
        err_log("Code file brocken, "
                "expected to read %d bytes, actually read %d\n",
                num_code_updates * bs, rbytes);
        return -EINVAL;
    }

    /* Compute new redundancices */
    err = ibv_exp_ec_update_sync(ec_ctx->calc, &ec_ctx->umem,
                     data_updates, code_updates);
    if (err) {
        err_log("Failed ibv_exp_ec_update (%d)\n", err);
        return err;
    }

    /* Write new redundancies into code file */
    err = write_by_pattern(ctx->codefd, stripe * m * bs, m, bs,
                 code_updates, ec_ctx->code.buf, 0, rbytes);

    if (err < 0)
        return err;

    return 0;
}

/*
 * Fills sg data entries with original data blocks and random data blocks.
 * Replaces required data blocks with random blocks in data file.
 * Return: number of data bytes read from file on success, errno on fail.
 */
static int
prep_data(struct updater_context *ctx, int stripe)
{
    struct ec_context *ec_ctx = ctx->ec_ctx;
    int k = ec_ctx->attr.k;
    int bs = ec_ctx->block_size;
    uint8_t *data_updates = ec_ctx->data_updates_arr;
    int i, rbytes, bytes, left, err;
    int pos = stripe * k * bs;
    int num_code_updates = ec_ctx->num_code_updates;
    uint8_t *data_buf = ec_ctx->udata.buf + num_code_updates * bs;

    /* Read relevant data from file */
    rbytes = read_by_pattern(ctx->datafd, pos, k, bs, data_updates,
                 data_buf, 1);
    if (rbytes <= 0)
        return rbytes;

    /* Create random data */
    for (left = rbytes, i = 0; left >=0; left -= bs, i++) {
        bytes = left < bs ? left : bs;
        rand_str(data_buf + (2 * i + 1) * bs, bytes);
    }

    /* Replace relevant data blocks by random data */
    err = write_by_pattern(ctx->datafd, pos, k, bs, data_updates,
                   data_buf + bs, 1, rbytes);
    if (err < 0) {
        err_log("Failed to update data file\n");
        return err;
    }

    return rbytes;
}

static int
update_file(struct updater_context *ctx)
{
    struct ec_context *ec_ctx = ctx->ec_ctx;
    int m = ec_ctx->attr.m;
    int bs = ec_ctx->block_size;
    uint8_t *code_updates = ec_ctx->code_updates_arr;
    uint8_t *code_not_updates;
    int num_data_updates = ec_ctx->num_data_updates;
    int num_code_updates = ec_ctx->num_code_updates;
    int stripe = 0, err, i;
    uint64_t seed;;

    /* Set seed */
    seed = time(NULL) - getpid();
    info_log("Seed %ld\n", seed);
    srand(seed);

    /* Set complementary code blocks */
    code_not_updates = calloc(1, m * bs);
    for (i = 0; i < m; i++)
        code_not_updates[i] = !code_updates[i];

    /* Compute */
    while (1) {
        info_log("Stripe %d\n", stripe);

        /* Prepare data */
        err = prep_data(ctx, stripe);
        if (err <= 0)
            return err;

        /* Prepare for code computation */
        ec_ctx->umem.num_code_sge = num_code_updates;
        ec_ctx->umem.num_data_sge = ec_ctx->umem.num_code_sge +
                        2 * num_data_updates;

        /* Compute required code */
        err = compute_code(ctx, stripe, code_updates, num_code_updates);
        if (err < 0)
            return err;

        if (num_code_updates == m)
            goto done;

        /* Prepare data for complementary computation */
        memset(ec_ctx->code.buf, 0, num_code_updates * bs);
        memmove(ec_ctx->udata.buf + (m - num_code_updates) * bs,
            ec_ctx->udata.buf + num_code_updates * bs,
            2 * num_data_updates * bs);

        ec_ctx->umem.num_code_sge = m - num_code_updates;
        ec_ctx->umem.num_data_sge = ec_ctx->umem.num_code_sge +
                        2 * num_data_updates;

        /* Compute complementary code */
        err = compute_code(ctx, stripe, code_not_updates, m - num_code_updates);
        if (err < 0)
            return err;

        /* Updates for the next loop */
done:
        memset(ec_ctx->code.buf, 0, m * bs);
        memset(ec_ctx->udata.buf, 0, m * bs + (num_data_updates * 2) * bs);
        stripe = stripe + 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct updater_context *ctx;
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

    err = update_file(ctx);
    if (err)
        err_log("failed to update encode for file %s\n", in.datafile);

    close_ctx(ctx);
    return err;
}
