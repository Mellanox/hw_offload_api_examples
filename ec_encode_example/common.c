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

#include "common.h"

struct sockaddr_storage ssin;
uint16_t port;
int verbose = 0;
int debug = 0;


int common_process_inargs(int argc, char *argv[],
                          char *opt_str,
                          struct option *long_options,
                          struct inargs *in,
                          void (*usage)(const char *))
{
    in->devname = NULL;
    in->frame_size = 1000;
    in->datafile = NULL;
    in->codefile = NULL;
    in->k = 10;
    in->m = 4;
    in->w = 4;
    in->data_updates = NULL;
    in->code_updates = NULL;
    in->unit = "MBps";
    in->max_inflight_calcs = 1;
    in->aff = 0;
    in->sw = 0;
    in->polling = 0;
    in->in_memory = 0;
    in->threads = 1;

    while (1) {
        int c, ret;

        c = getopt_long(argc, argv, opt_str, long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ret = get_addr(optarg, (struct sockaddr *)&ssin);
            break;

        case 'i':
            ret = asprintf(&in->devname, optarg);
            if (ret < 0) {
                err_log("failed devname asprintf\n");
                return ret;
            }
            break;

        case 'D':
            ret = asprintf(&in->datafile, optarg);
            if (ret < 0) {
                err_log("failed data file asprintf\n");
                return ret;
            }
            break;

        case 'C':
            ret = asprintf(&in->codefile, optarg);
            if (ret < 0) {
                err_log("failed code file asprintf\n");
                return ret;
            }
            break;

        case 'E':
            ret = asprintf(&in->failed_blocks, optarg);
            if (ret < 0) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;
        case 'u':
            ret = asprintf(&in->data_updates, optarg);
            if (ret < 0) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'c':
            ret = asprintf(&in->code_updates, optarg);
            if (ret < 0) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 's':
            in->frame_size = strtol(optarg, NULL, 0);
            if (in->frame_size < 0) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'k':
            in->k = strtol(optarg, NULL, 0);
            if (in->k <= 0 || in->k > 256) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'm':
            in->m = strtol(optarg, NULL, 0);
            if (in->m <= 0) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'w':
            in->w = strtol(optarg, NULL, 0);
            if (in->w != 1 && in->w != 2 && in->w != 4 && in->w != 8) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'q':
            in->depth = strtol(optarg, NULL, 0);
            if (in->depth <= 0) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'r':
            in->duration = strtol(optarg, NULL, 0);
            if (in->duration <= 0) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'f':
            in->aff = strtol(optarg, NULL, 0);
            break;

        case 'S':
            in->sw = 1;
            break;

        case 'U':
            ret = asprintf(&in->unit, optarg);
            if (ret < 0) {
                err_log("failed units asprintf\n");
                return ret;
            }
            break;

        case 'l':
            in->max_inflight_calcs = strtol(optarg, NULL, 0);
            if (in->max_inflight_calcs < 1) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 't':
            in->threads = strtol(optarg, NULL, 0);
            if (in->threads < 1) {
                usage(argv[0]);
                return -EINVAL;
            }
            break;

        case 'p':
            in->polling = 1;
            break;

        case 'n':
            in->in_memory = 1;
            break;

        case 'v':
            verbose = 1;
            break;

        case 'd':
            debug = 1;
            break;

        case 'h':
            usage(argv[0]);
            exit(0);

        default:
            usage(argv[0]);
            return -EINVAL;
        }
    }

    if (in->w != 8 && in->k > 16) {
        err_log("Bad K(%d) val for W(%d)\n", in->k, in->w);
        usage(argv[0]);
        return -EINVAL;
    }

    return 0;
}

int get_addr(char *dst, struct sockaddr *addr)
{
    struct addrinfo *res;
    int ret;

    ret = getaddrinfo(dst, NULL, NULL, &res);
    if (ret) {
        printf("getaddrinfo failed - invalid hostname or IP address\n");
        return ret;
    }

    if (res->ai_family == PF_INET)
        memcpy(addr, res->ai_addr, sizeof(struct sockaddr_in));
    else if (res->ai_family == PF_INET6)
        memcpy(addr, res->ai_addr, sizeof(struct sockaddr_in6));
    else
        ret = -1;

    freeaddrinfo(res);

    return ret;
}
