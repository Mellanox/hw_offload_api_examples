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
#include <signal.h>
#include <sys/time.h>

enum state {
	START_STATE,
	STOP_STATE,
};

volatile enum state state = START_STATE;
static int duration = 10;

struct encoder_context {
	struct ibv_context	*context;
	struct ibv_pd		*pd;
	struct ec_context	*ec_ctx;
	int			infd;
	int			outfd_sw;
	int			outfd_off;
	unsigned long long	bytes;
	int			sw;
};

static struct encoder_context *
init_ctx(struct ibv_device *ib_dev, struct inargs *in)
{
	struct encoder_context *ctx;

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
				   in->k, in->m, in->w, in->aff, 1, NULL, NULL, NULL);
	if (!ctx->ec_ctx) {
		err_log("Failed to allocate EC context\n");
		goto dealloc_pd;
	}

	ctx->sw = in->sw;
	return ctx;

dealloc_pd:
	ibv_dealloc_pd(ctx->pd);
close_device:
	ibv_close_device(ctx->context);
free_ctx:
	free(ctx);

	return NULL;
}

static void close_ctx(struct encoder_context *ctx)
{
	free_ec_ctx(ctx->ec_ctx);
	ibv_dealloc_pd(ctx->pd);

	if (ibv_close_device(ctx->context))
		err_log("Couldn't release context\n");


	free(ctx);
}

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            start EC encoder\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -i, --ib-dev=<dev>         use IB device <dev> (default first device found)\n");
	printf("  -k, --data_blocks=<blocks> Number of data blocks\n");
	printf("  -m, --code_blocks=<blocks> Number of code blocks\n");
	printf("  -w, --gf=<gf>              Galois field GF(2^w)\n");
	printf("  -D, --datafile=<name>      Name of input file to encode\n");
	printf("  -s, --frame_size=<size>    size of EC frame\n");
	printf("  -r, --duration=<duration>  duration in seconds\n");
	printf("  -f, --affinity=<affinity>  affinity\n");
	printf("  -U, --unit=<unit>          measure unit (MBps/Gbps\n");
	printf("  -d, --debug                print debug messages\n");
	printf("  -v, --verbose              add verbosity\n");
	printf("  -h, --help                 display this output\n");
}

static int process_inargs(int argc, char *argv[], struct inargs *in)
{
	int err;
	struct option long_options[] = {
		{ .name = "ib-dev",        .has_arg = 1, .val = 'i' },
		{ .name = "datafile",      .has_arg = 1, .val = 'D' },
		{ .name = "frame_size",    .has_arg = 1, .val = 's' },
		{ .name = "data_blocks",   .has_arg = 1, .val = 'k' },
		{ .name = "code_blocks",   .has_arg = 1, .val = 'm' },
		{ .name = "gf",            .has_arg = 1, .val = 'w' },
		{ .name = "duration",      .has_arg = 1, .val = 'r' },
		{ .name = "unit",          .has_arg = 1, .val = 'U' },
		{ .name = "sw",            .has_arg = 0, .val = 'S' },
		{ .name = "debug",         .has_arg = 0, .val = 'd' },
		{ .name = "verbose",       .has_arg = 0, .val = 'v' },
		{ .name = "affinity",      .has_arg = 1, .val = 'f' },
		{ .name = "help",          .has_arg = 0, .val = 'h' },
		{ 0 }
	};

	err = common_process_inargs(argc, argv, "i:D:E:s:k:m:r:w:f:U:Shdv",
				    long_options, in, usage);
	if (err)
		return err;

	if (in->duration)
		duration = in->duration;

	if (in->frame_size <= 0) {
		err_log("No frame_size given %d\n", in->frame_size);
		return -EINVAL;
	}

	return 0;
}

void catch_alarm(int sig)
{
	printf("GOT sigalarm %d cur_state %d\n", sig, state);
	if (sig == SIGKILL) {
		state = STOP_STATE;
		return;
	}

	switch (state) {
		case START_STATE:
			state = STOP_STATE;
			break;
		default:
			printf("unknown state\n");
	}
}

static int encode_file(struct encoder_context *ctx)
{
	struct ec_context *ec_ctx = ctx->ec_ctx;
	int err;
	struct timeval tvalBefore, tvalAfter;

	gettimeofday(&tvalBefore, NULL);
	gettimeofday(&tvalAfter, NULL);
	while (tvalAfter.tv_sec - tvalBefore.tv_sec < (long)duration) {
		if (ctx->sw)
			err = sw_ec_encode(ctx->ec_ctx->data.buf,
					   ctx->ec_ctx->code.buf,
					   ctx->ec_ctx->attr.encode_matrix,
					   ctx->ec_ctx->block_size,
					   ctx->ec_ctx->attr.k,
					   ctx->ec_ctx->attr.m);
		else
			err = ibv_exp_ec_encode_sync(ec_ctx->calc, &ec_ctx->mem);
		if (err) {
			err_log("Failed ibv_exp_ec_encode (%d)\n", err);
			return err;
		}
		ctx->bytes += ec_ctx->block_size * ec_ctx->attr.k;

		gettimeofday(&tvalAfter, NULL);
	}

	return 0;
}

static void print_report(struct encoder_context *ctx, char* unit)
{
	double m_bw, g_bw;

	if (!strcmp(unit, "MBps")) {
		m_bw = (float)ctx->bytes / duration / 1024 / 1024;
		printf("%lf m_bw\n", m_bw);
	} else if (!strcmp(unit, "Gbps")) {
		g_bw = (float)ctx->bytes * 8 / duration / 1000000000;
		printf("%lf g_bw\n", g_bw);
	}
	else
		printf("Unknown type of unit: %s\n", unit);
}

int main(int argc, char *argv[])
{
	struct encoder_context *ctx;
	struct ibv_device *device;
	struct inargs in;
	int err;
	struct sigaction sa = { .sa_handler = NULL };

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = catch_alarm;
	sigaction(SIGKILL, &sa, 0);

	err = process_inargs(argc, argv, &in);
	if (err)
		return err;

	device = find_device(in.devname);
	if (!device)
		return -EINVAL;

	ctx = init_ctx(device, &in);
	if (!ctx)
		return -ENOMEM;

	err = encode_file(ctx);
	if (err)
		err_log("failed to encode file %s\n", in.datafile);

	print_report(ctx, in.unit);

	close_ctx(ctx);

	return 0;
}
