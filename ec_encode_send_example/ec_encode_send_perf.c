#include "ec_common.h"

struct config_t config = {
	.dev_name	= NULL,
	.server_name	= NULL,
	.tcp_port	= 19875,
	.ib_port	= 1,
	.gid_idx	= -1,
	.input_file_name = NULL,
	.time		= 10,
	.block_size	= 512,
	.k		= 3,
	.m		= 2,
	.w		= 8,
	.max_inflight_calcs = 1
};

static int
receive_file(struct resources *res)
{
	int rc = 0;
	uint32_t tmp;
	size_t total_size = 0;
	struct timeval tvalBefore, tvalAfter;
	struct ec_block *ecb;

	sock_sync_data(res->sock, sizeof(config.time), (char *)&tmp, (char *)&config.time);
	/* Add some time to test duration on server side */
	config.time += 1;

	gettimeofday(&tvalBefore, NULL);
	gettimeofday(&tvalAfter, NULL);

	while (ecb = get_ec_block(res)) {
		ecb->pending_comps = config.k + config.m;
		post_receive_block(res, ecb);
	}
	while (tvalAfter.tv_sec - tvalBefore.tv_sec < (long)config.time) {
		struct ibv_wc wc;
		rc = poll_completions(res, &wc, 1);
		if (rc < 0) {
			fprintf(stderr, "Failed to poll for completion\n");
			goto receive_file_exit;
		} else if (rc == 0) {
			rc = 0;
			goto receive_file_done;
		}
		rc = 0;
		ecb = (struct ec_block *)wc.wr_id;
		if (0 == --ecb->pending_comps) {
			ecb->pending_comps = config.k + config.m;
			post_receive_block(res, ecb);
			total_size += config.block_size * config.k;
		}
		gettimeofday(&tvalAfter, NULL);
	}

 receive_file_done:
	if (sock_sync_data(res->sock, sizeof(tmp), (char *)&tmp, (char *)&tmp)) {
		fprintf(stderr, "Failed to sync after completion\n");
		rc = 1;
		goto receive_file_exit;
	}

	fprintf(stdout, "Received %lu bytes in %lu seconds, bandwidth %.1f MiB/s\n",
		total_size,
		tvalAfter.tv_sec - tvalBefore.tv_sec,
		(double)total_size / 1024 / 1024 / (tvalAfter.tv_sec - tvalBefore.tv_sec));

 receive_file_exit:
	return rc;
}

int server(struct resources *res)
{
	int rc = 0;

	rc = receive_file(res);
	if (rc) {
		goto err_exit;
	}
	rc = receive_file(res);
	if (rc) {
		goto err_exit;
	}
err_exit:
	return rc;
}

static int
encode_and_send_file(struct resources *res,
		     int (*encode_fn)(struct resources *, struct ec_block *))
{
	int rc = 0;
	uint32_t tmp;
	size_t total_size = 0;
	struct timeval tvalBefore, tvalAfter;
	struct ibv_wc wc[MAX_CQE];
	uint64_t total_ecb_time_ns = 0;
	uint64_t ecb_count = 0;

	sock_sync_data(res->sock, sizeof(config.time), (char *)&config.time, (char *)&tmp);

	gettimeofday(&tvalBefore, NULL);
	gettimeofday(&tvalAfter, NULL);
	while (tvalAfter.tv_sec - tvalBefore.tv_sec < (long)config.time) {
		int i;
		struct ec_block *ecb;
		int has_blocks;

		while (ecb = get_ec_block(res)) {
			clock_gettime(CLOCK_MONOTONIC, &ecb->submit_time);
			ecb->pending_comps = config.k + config.m;
			rc = encode_fn(res, ecb);
			if (rc) {
				rc = 1;
				goto encode_and_send_file_exit;
			}
			total_size += config.block_size * config.k;
		}
		has_blocks = 0;
		while (!has_blocks) {
			rc = poll_completions(res, wc, MAX_CQE);
			if (rc <= 0) {
				goto encode_and_send_file_exit;
			}
			for (i = 0; i < rc; ++i) {
				if (wc[i].status != 0) {
					fprintf(stderr, "Got completion with error: %d\n", wc[i].status);
					goto encode_and_send_file_exit;
				}
				ecb = (struct ec_block*)wc[i].wr_id;
				if (0 == --ecb->pending_comps) {
					struct timespec t;
					clock_gettime(CLOCK_MONOTONIC, &t);
					total_ecb_time_ns += (uint64_t) (t.tv_sec - ecb->submit_time.tv_sec) * 1000000000
						+ (t.tv_nsec - ecb->submit_time.tv_nsec);
					ecb_count++;
					put_ec_block(res, ecb);
					has_blocks++;
				}
			}
			rc = 0;
		}
		gettimeofday(&tvalAfter, NULL);
	}

	if (sock_sync_data(res->sock, sizeof(tmp), (char *)&tmp, (char *)&tmp)) {
		fprintf(stderr, "Failed to sync after completion\n");
		goto encode_and_send_file_exit;
	}

	fprintf(stdout, "Encoded and sent %lu bytes in %lu seconds, bandwidth %.1f MiB/s, time per block %.2f us\n",
		total_size,
		tvalAfter.tv_sec - tvalBefore.tv_sec,
		(double)total_size / 1024 / 1024 / (tvalAfter.tv_sec - tvalBefore.tv_sec),
		(double)total_ecb_time_ns / ecb_count);

 encode_and_send_file_exit:
	return rc;
}


int client(struct resources *res)
{
	int rc = 0;

	rc = encode_and_send_file(res, encode_and_send_block);
	if (rc) {
		goto err_exit;
	}
	rc = encode_and_send_file(res, encode_and_send_block_sw);
	if (rc) {
		goto err_exit;
	}
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

	fprintf(stdout, " Time : %u\n", config.time);
	fprintf(stdout, " Block size : %u\n", config.block_size);
	fprintf(stdout, " K : %u\n", config.k);
	fprintf(stdout, " M : %u\n", config.m);
	fprintf(stdout, " Max inflight calcs : %u\n", config.max_inflight_calcs);
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
	fprintf(stdout, " %s [options] start a server and wait for connection\n", argv0);
	fprintf(stdout, " %s [options] <host> connect to server at <host>\n", argv0);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout,
		" -p, --port <port>            listen on/connect to port <port> (default 18515)\n");
	fprintf(stdout,
		" -d, --ib-dev <dev>           use IB device <dev> (default first device found)\n");
	fprintf(stdout,
		" -i, --ib-port <port>         use port <port> of IB device (default 1)\n");
	fprintf(stdout,
		" -g, --gid_idx <git index>    gid index to be used in GRH "
		"(default not used)\n");
	fprintf(stdout,
		" -t, --time <seconds>         test time\n");
	fprintf(stdout,
		" -b, --block-size <size>      size of data block (default 512)\n");
	fprintf(stdout,
		" -k, --data-devices <N>       number of data devices (default 3, max 16)\n");
	fprintf(stdout,
		" -m, --code-devices <N>       number of code devices (default 2, max 4)\n");
	fprintf(stdout,
		" -l, --calcs <N>              max number of inflight calculations (default 1, max %d)\n",
		MAX_INFLIGHT_CALCS);
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
	int i;
	char temp_char;

	/* parse the command line parameters */
	while (1) {
		int c;
		static struct option long_options[] = {
			{ .name = "port",		.has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",		.has_arg = 1, .val = 'd' },
			{ .name = "ib-port",		.has_arg = 1, .val = 'i' },
			{ .name = "gid-idx",		.has_arg = 1, .val = 'g' },
			{ .name = "time",		.has_arg = 1, .val = 't' },
			{ .name = "block-size",	.has_arg = 1, .val = 'b' },
			{ .name = "k",			.has_arg = 1, .val = 'k' },
			{ .name = "m",			.has_arg = 1, .val = 'm' },
			{ .name = "l",			.has_arg = 1, .val = 'l' },
			{ .name = "help",		.has_arg = 0, .val = 'h' },
			{ .name = NULL,		.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "p:d:i:g:t:b:k:m:l:h", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
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
		case 't':
			config.time = strtoul(optarg, NULL, 0);
			if (config.time < 0) {
				usage(argv[0]);
				return 1;
			};
			break;
		case 'b':
			config.block_size = strtoul(optarg, NULL, 0);
			break;
		case 'k':
			config.k = strtoul(optarg, NULL, 0);
			if ((config.k < 1) ||(config.k > MAX_K)) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'm':
			config.m = strtoul(optarg, NULL, 0);
			if ((config.m < 1) || (config.m > MAX_M)) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'l':
			config.max_inflight_calcs = strtoul(optarg, NULL, 0);
			if ((config.max_inflight_calcs < 1) ||
			    (config.max_inflight_calcs > MAX_INFLIGHT_CALCS)) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'h':
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

	if (resources_create(&res)) {
		fprintf(stderr, "failed to create resources\n");
		goto main_exit;
	}

	if (connect_qps(&res)) {
		fprintf(stderr, "failed to connect QPs\n");

		goto main_exit;
	}

	fprintf(stdout, "Data QPs: ");
	for (i = 0; i < config.k; ++i) {
		fprintf(stdout, "%x, ", res.qps[i]->qp_num);
	}
	fprintf(stdout, "\nCode QPs: ");
	for (i = 0; i < config.m; ++i) {
		fprintf(stdout, "%x, ", res.qps[config.k + i]->qp_num);
	}
	fprintf(stdout, "\n");
	if (config.server_name)
		rc = client(&res);
	else
		rc = server(&res);

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
