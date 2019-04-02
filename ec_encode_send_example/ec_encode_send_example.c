#include "ec_common.h"

struct config_t config = {
	.dev_name	= NULL,
	.server_name	= NULL,
	.tcp_port	= 19875,
	.ib_port	= 1,
	.gid_idx	= -1,
	.input_file_name = NULL,
	.block_size	= 512,
	.k		= 3,
	.m		= 2,
	.w		= 8,
	.max_inflight_calcs = 1
};

static int
receive_file(struct resources *res, const char *file_suffix)
{
	FILE *fds[config.k + config.m];
	int rc = 0;
	int i;
	uint32_t fsize;
	uint32_t flen = 0;
	uint32_t tmp;

	sock_sync_data(res->sock, sizeof(fsize), (char *)&tmp, (char *)&fsize);
	fsize = ntohl(fsize);

	memset(fds, 0, sizeof(fds));
	for (i = 0; i < config.k + config.m; ++i) {
		char fname[1024];
		snprintf(fname, sizeof(fname), "%s%02d%s",
			 (i < config.k) ? "data" : "code", i, file_suffix);
		fds[i] = fopen(fname, "w");
		if (!fds[i]) {
			rc = 1;
			goto receive_file_exit;
		}
	}

	while (flen < fsize) {
		struct ec_block *ecb = &res->ec_blocks[0];
		post_receive_block(res, ecb);
		for (i = 0; i < config.k + config.m; ++i) {
			struct ibv_wc wc;
			rc = poll_completions(res, &wc, 1);
			if (rc <= 0) {
				fprintf(stderr, "Failed to poll for completion %d\n", i);
				goto receive_file_exit;
			}
			rc = 0;
		}
		for (i = 0; i < config.k + config.m; ++i) {
			size_t len;
			len = fwrite(ecb->buf + i * config.block_size,
				     1, config.block_size, fds[i]);
			if (!len) {
				fprintf(stderr, "Failed to read input file\n");
				rc = 1;
				goto receive_file_exit;
			}
		}
		flen += config.block_size * config.k;
	}

 receive_file_exit:
	for (i = 0; i < config.k + config.m; ++i) {
		if (fds[i]) {
			fclose(fds[i]);
		}
	}
	return rc;
}

int server(struct resources *res)
{
	int rc = 0;

	rc = receive_file(res, "_hw");
	if (rc) {
		goto err_exit;
	}
	rc = receive_file(res, "_sw");
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
	FILE *fd = NULL;
	int rc = 0;
	uint32_t fsize;
	uint32_t tmp;

	fd = fopen(config.input_file_name, "r");
	if (!fd) {
		rc = 1;
		goto encode_and_send_file_exit;
	}

	fseek(fd, 0, SEEK_END);
	fsize = ftell(fd);
	rewind(fd);
	fsize = htonl(fsize);
	sock_sync_data(res->sock, sizeof(fsize), (char *)&fsize, (char *)&tmp);

	while (!feof(fd)) {
		int i;
		struct ibv_wc wc;
		size_t len = config.block_size * config.k;
		struct ec_block *ecb = &res->ec_blocks[0];

		memset(ecb->buf, 0, len);
		len = fread(ecb->buf, 1, len, fd);
		if (!len) {
			fprintf(stderr, "Failed to read input file\n");
			rc = 1;
			goto encode_and_send_file_exit;
		}
		rc = encode_fn(res, ecb);
		if (rc) {
			goto encode_and_send_file_exit;
		}
		for (i = 0; i < config.k + config.m; ++i) {
			rc = poll_completions(res, &wc, 1);
			if (rc <= 0) {
				goto encode_and_send_file_exit;
			}
			rc = 0;
		}
	}

 encode_and_send_file_exit:
	if (fd) {
		fclose(fd);
	}
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

	fprintf(stdout, " Input file name : %u\n", config.input_file_name);
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
		" -f, --input-file <path>      input file name\n");
	fprintf(stdout,
		" -b, --block-size <size>      size of data block (default 512)\n");
	fprintf(stdout,
		" -k, --data-devices <N>       number of data devices (default 3, max 16)\n");
	fprintf(stdout,
		" -m, --code-devices <N>       number of code devices (default 2, max 4)\n");
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
			{ .name = "input-file",	.has_arg = 1, .val = 'f' },
			{ .name = "block-size",	.has_arg = 1, .val = 'b' },
			{ .name = "k",			.has_arg = 1, .val = 'k' },
			{ .name = "m",			.has_arg = 1, .val = 'm' },
			{ .name = "help",		.has_arg = 0, .val = 'h' },
			{ .name = NULL,		.has_arg = 0, .val = '\0' }
		};

		c = getopt_long(argc, argv, "p:d:i:g:f:b:k:m:h", long_options, NULL);
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
		case 'f':
			config.input_file_name = strdup(optarg);
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
