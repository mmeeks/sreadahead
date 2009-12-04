/*
 * (C) Copyright 2008 Intel Corporation
 *
 * Author: Arjan van de Ven <arjan@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/times.h>
#include <string.h>
#include <pthread.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <errno.h>
#include <linux/fs.h>

#include <getopt.h>

#define VERSION "1.0"

#undef HAVE_IO_PRIO
#if defined(__i386__)
#  define HAVE_IO_PRIO
#  define __NR_ioprio_set 289
#elif defined(__x86_64__)
#  define HAVE_IO_PRIO
#  define __NR_ioprio_set 251
#elif defined(__powerpc__)
#  define HAVE_IO_PRIO
#  define __NR_ioprio_set 273
#else /* not fatal */
#  warning "Architecture does not support ioprio modification"
#endif
#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_WHO_PGRP    2
#define IOPRIO_CLASS_RT 1
#define IOPRIO_CLASS_BE 2
#define IOPRIO_CLASS_IDLE 3
#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_IDLE_LOWEST (7 | (IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT))
#define IOPRIO_BE_HIGHEST  (0 | (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT))
#define IOPRIO_RT_HIGHEST  (0 | (IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT))

#define PACK_PATH	"/var/lib/sreadahead"
#define DEBUGFS_MNT	"/var/lib/sreadahead/debugfs"
#define PACK_FILE	"/var/lib/sreadahead/pack"

#define MAXR 40000	/* trace file can be long */
#define MAXFL 128
#define MAXRECS 6	/* reduce nr of fragments to this amount */
#define MAXTHREADS 16   /* max. number of read threads we can use */

#define DEFAULT_MAX_TIME 20 /* should be enough for every OS to boot */

#define CHUNK_SIZE 256 /* deeply mystical I/O grouping chunk size */

/*
 * By default, the kernel reads ahead for 128kb. This throws off our
 * measurements since we don't need the extra 128kb for each file.
 * On top of that, at the accelerated boot, we would be reading another
 * 128kb too much potentially, wasting a lot of time.
 *
 * By lowering the read_ahead_kb, we get more fragments (since they
 * are not glued together by the artifical kernel readahead). So
 * lowering this number too much doesn't actually gain much.
 *
 * XX kb seems to be a good balance with not too many fragments, but
 * keeping the total size low enough to make a difference.
 *
 * 8-16kb seems to be a good median value, with good total size savings
 * over anything higher. Lower sizes result in more separate blocks
 * and only minimal total size savings.
 */
#define RA_NORMAL 128	/* default read_ahead_kb size */
#define RA_SMALL  16	/* our tuned down value */

struct ra_record {
	uint32_t		offset;
	uint32_t		len;
};

/* disk format used, when reading pack */
struct ra_disk {
	char			filename[MAXFL];
	struct ra_record	data[MAXRECS];
};

/* memory format used with sorting/filtering */
struct ra_struct {
	char			filename[MAXFL];
	struct ra_record	data[MAXRECS];
	struct ra_struct	*next;
	struct ra_struct	*prev;
	int			number;
	unsigned long		block_order_hint;
};

static struct ra_struct *ra[MAXR];
static struct ra_disk rd[MAXR];
static struct ra_struct *first_ra;
static int racount = 0;
static int rdcount = 0;
static int fcount = 0;
static int rdsize = 0;

static unsigned int total_files = 0;
static unsigned int cursor = 0;

static int debug = 0;
static int is_ssd = 0;

static void set_ioprio (int prio)
{
#ifdef HAVE_IO_PRIO
	if (syscall(__NR_ioprio_set, IOPRIO_WHO_PGRP, 0, prio) == -1)
		perror("Can not set IO priority to idle class");
#endif
}

static int sysfs_unmount = 0;
static void enter_sysfs (void)
{
	int unmount;

	unmount = chdir("/sys/block");
	if (unmount != 0) {
		if (mount("sysfs", "/sys", "sysfs", 0, NULL) != 0) {
			perror("Unable to mount sysfs\n");
			/* non-fatal */
			return;
		}
		sysfs_unmount = 1;
		chdir("/sys/block");
	} else
		sysfs_unmount = 0;
}

static void exit_sysfs (void)
{
	chdir("/");
	if (sysfs_unmount != 0)
		umount("/sys");
}

static int debugfs_unmount = 0;
static void enter_debugfs (void)
{
	/*
	 * by now the init process should have mounted debugfs on a logical
	 * location like /sys/kernel/debug, but if not then we temporarily
	 * re-mount it ourselves
	 */
	debugfs_unmount = chdir("/sys/kernel/debug/tracing");
	if (debugfs_unmount != 0) {
		int ret = mount("debugfs", DEBUGFS_MNT, "debugfs", 0, NULL);
		if (ret != 0) {
			perror("Unable to mount debugfs\n");
			exit(EXIT_FAILURE);
		}
		chdir(DEBUGFS_MNT);
	} else {
		chdir("..");
	}
}

static void exit_debugfs (void)
{
	chdir("/");
	if (debugfs_unmount != 0) {
		umount(DEBUGFS_MNT);
	}
}

static int is_sda_ssd (void)
{
	FILE *file;
	int is_ssd = 0;

	enter_sysfs();

	file = fopen ("sda/queue/rotational", "r");
	if (file) {
		char buffer[64];
		is_ssd = !atoi (fgets (buffer, 64, file));
		fclose (file);
	}

	exit_sysfs();

	return is_ssd;
}

static void readahead_set_len(int size)
{
	int i = 0;
	char ractl[100];
	/* changes readahead size to "size" for local block devices */

	enter_sysfs();

	sprintf(ractl, "sda/queue/read_ahead_kb");
	while (i <= 3) {
		/* check first 4 sata discs */
		FILE *file = fopen(ractl, "w");
		if (file) {
			fprintf(file, "%d", size);
			fclose(file);
		}
		ractl[2]++; /* a -> b, etc */
		i++;
	}

	exit_sysfs();
}

static void kmsg_print(const char *msg)
{
	int fd = open("/dev/kmsg", O_WRONLY);
	if (fd > 0) {
		write (fd, msg, strlen (msg));
		close (fd);
	}
}

static void readahead_one(int index)
{
	int fd;
	int i;
	char buf[128];

	if (index == CHUNK_SIZE) {
		kmsg_print ("sreadahead hdd - read first chunk\n");
		set_ioprio (IOPRIO_IDLE_LOWEST);
	}

	fd = open(rd[index].filename, O_RDONLY|O_NOATIME);
	if (fd < 0)
		fd = open(rd[index].filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: open failed (%s)\n",
			rd[index].filename, strerror_r(errno, buf, sizeof buf));
		return;
	}

	for (i = 0; i < MAXRECS; i++) {
		if (rd[index].data[i].len)
			readahead(fd, rd[index].data[i].offset,
				  rd[index].data[i].len);
	}
	close(fd);
}

static void *one_thread(void *ptr)
{
	while (1) {
		unsigned int mine;

		mine = __sync_fetch_and_add(&cursor, 1);
		if (mine < total_files)
			readahead_one(mine);
		else
			break;
	}
	return NULL;
}

/* sort to help remove duplicates, we retain the original
   order in the next/prev linked list */
static void sort_ra_by_name(void)
{
	int delta = 1;

	while (delta > 0) {
		int i;
		delta = 0;
		for (i = 0; i < racount - 1; i++) {
			int c;

			c = strcmp(ra[i]->filename, ra[i+1]->filename);
			if (c > 0) {
				struct ra_struct *tmp;
				tmp = ra[i];
				ra[i] = ra[i+1];
				ra[i+1] = tmp;
				delta++;
			}
		}
	}
}

static void remove_dupes(void)
{
	int i;
	int j;

	for (i = 0; i < racount - 1; i++) {
		for (j = i + 1; j < racount; j++) {
			if (!ra[i])
				break;

			if (strcmp(ra[i]->filename, ra[j]->filename) != 0) {
				i = j - 1;
				break;
			}
			if (ra[j]->next)
				ra[j]->next->prev = ra[j]->prev;
			if (ra[j]->prev)
				ra[j]->prev->next = ra[j]->next;
			free(ra[j]);
			ra[j] = NULL;
		}
	}
}

static int smallest_gap(struct ra_record *record, int count)
{
	int i;
	int cur = 0, maxgap;

	maxgap = 1024*1024*512;
	
	for (i = 0; i < count; i++, record++) {
		if ((i + 1) < count) {
			int gap;
			gap = (record + 1)->offset - record->offset - record->len;
			if (gap < maxgap) {
				maxgap = gap;
				cur = i;
			}
		}
	}
	return cur;
}

static int merge_record(struct ra_record *record, int count, int to_merge)
{
	record[to_merge].len = record[to_merge+1].offset
			       + record[to_merge+1].len - record[to_merge].offset;
	memcpy(&record[to_merge+1], &record[to_merge+2],
		sizeof(struct ra_record) * (count-to_merge - 2));
	return count - 1;
}

static int reduce_blocks(struct ra_record *record, int count, int target)
{
	while (count > target) {
		int tomerge;
		tomerge = smallest_gap(record, count);
		count = merge_record(record, count, tomerge);
	}
	return count;
}

static int get_blocks(struct ra_struct *r)
{
	FILE *file;
	int fd;
	struct stat statbuf;
	void *mmapptr;
	unsigned char *mincorebuf;
	struct ra_record record[4096];
	int rcount = 0;
	int phase;
	uint32_t start = 0;
	int there = 0;
	int notthere = 0;
	int i;

	if (!r)
		return 0;

	file = fopen(r->filename, "r");
	if (!file)
		return 0;

	fd = fileno(file);
	fstat(fd, &statbuf);
	/* prevent accidentally reading from a pipe */
	if (!(S_ISREG(statbuf.st_mode))) {
		fclose(file);
		return 0;
	}

	memset(record, 0, sizeof(record));

	mmapptr = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);

	mincorebuf = malloc(statbuf.st_size/4096 + 1);
	mincore(mmapptr, statbuf.st_size, mincorebuf);

	if (mincorebuf[0]) {
		phase = 1;
		start = 0;
	} else {
		phase = 0;
	}

	for (i = 0; i <= statbuf.st_size; i += 4096) {
		if (mincorebuf[i / 4096])
			there++;
		else
			notthere++;
		if (phase == 1 && !mincorebuf[i / 4096]) {
			phase = 0;
			if (i > statbuf.st_size)
				i = statbuf.st_size + 1;
			record[rcount].offset = start;
			record[rcount].len = i - 1 - start;
			rcount++;
			if (rcount >= 4000) rcount = 4000;
		} else if (phase == 0 && mincorebuf[i / 4096]) {
			phase = 1;
			start = i;
		}
	}

	if (phase == 1) {
		if (i > statbuf.st_size)
			i = statbuf.st_size + 1;
		record[rcount].offset = start;
		record[rcount].len = i - 1 - start;
		rcount++;
	}

	if (there) {
		r->block_order_hint = 0; /* first block */
		ioctl (fd, FIBMAP, &r->block_order_hint);
	}

	free(mincorebuf);
	munmap(mmapptr, statbuf.st_size);
	fclose(file);
	
	rcount = reduce_blocks(record, rcount, MAXRECS);
	if (rcount > 0) {
		/* some empty files slip through */
		if (record[0].len == 0)
			return 0;

		if (debug) {
			int tlen = 0;
			int tc = 0;
			while (tc < rcount) {
				tlen += record[tc].len;
				tc++;
				fcount++;
			}
			rdsize += (tlen <= 0 ? 1024 : tlen);
			printf("%s: %d fragment(s), %dkb, %3.1f%% - block %ld\n",
			       r->filename, rcount,
			       (tlen <= 1024 ? 1024 : tlen) / 1024,
			       100.0 * there / (there + notthere),
			       r->block_order_hint);
		}

		memcpy(r->data, record, sizeof(r->data));
		return 1;
	}
	return 0;
}

static void get_ra_blocks(void)
{
	struct ra_struct *r = first_ra;

	while (r) {
		if (!get_blocks(r)) {
			/* no blocks, remove from list */
			if (r->next)
				r->next->prev = r->prev;
			if (r->prev)
				r->prev->next = r->next;
		}
		r = r->next;
	}
}

static void write_ra (FILE *file, struct ra_struct *r)
{
	if (debug)
		printf ("write_ra '%s' (0x%lx)\n", r->filename, r->block_order_hint);
	fwrite(r->filename, MAXFL, 1, file);
	fwrite(r->data, sizeof(r->data), 1, file);
	rdcount++;
}

/* split the list of files into chunks - runs of 256 files
   or so. Inside this chunk, sort by block hint - hopefully
   this substantially improves read linearity on non-SSDs */
static void write_sorted_in_chunks_by_block(FILE *file, struct ra_struct *list)
{
	while (list) {
		int i, max = 0;
		int delta = 1;
		struct ra_struct *sort_array[CHUNK_SIZE];

		/* copy a chunk across */
		for (; list && max < CHUNK_SIZE; list = list->next)
			sort_array[max++] = list;

		/* sort by first block */
		while (delta > 0) {
			delta = 0;
			for (i = 0; i < max - 1; i++) {
				if (sort_array[i]->block_order_hint > sort_array[i+1]->block_order_hint) {
					struct ra_struct *tmp;
					tmp = sort_array[i];
					sort_array[i] = sort_array[i+1];
					sort_array[i+1] = tmp;
					delta++;
				}
			}
		}

		/* write out */
		for (i = 0; i < max - 1; i++)
			write_ra (file, sort_array[i]);
	}
}

static void trace_fprintf (const char *fname, const char *value)
{
	FILE *file = fopen (fname, "w");
	if (!file) {
		fprintf (stderr, "Unable to open %s: %s\n",
			 fname, strerror (errno));
		exit(EXIT_FAILURE);
	}
	fputs (value, file);
	fclose(file);
}

static void trace_start(void)
{
	int ret;
	FILE *file;
	char buf[4096];

	/*
	 * at this time during boot we can guarantee that things like
	 * debugfs, sysfs are not mounted yet (at least they should be)
	 * so we mount it temporarily to enable tracing, and umount
	 */
	ret = mount("debugfs", DEBUGFS_MNT, "debugfs", 0, NULL);
	if (ret != 0) {
		perror("Unable to mount debugfs\n");
		exit(EXIT_FAILURE);
	}

	chdir(DEBUGFS_MNT);

	trace_fprintf ("tracing/events/fs/uselib/enable", "1");
	trace_fprintf ("tracing/events/fs/open_exec/enable", "1");
	trace_fprintf ("tracing/events/fs/do_sys_open/enable", "1");
	trace_fprintf ("tracing/tracing_enabled", "1");

	file = fopen("tracing/tracing_enabled", "r");
	fgets(buf, 4096, file);
	fclose(file);
	if (strcmp(buf, "1\n") != 0) {
		perror("Enabling tracing failed\n");
		exit(EXIT_FAILURE);
	}

	chdir("/");

	umount(DEBUGFS_MNT);

	/* set this low, so we don't readahead way too much */
	readahead_set_len(RA_SMALL);
}

static int trace_terminate = 0;
static void trace_signal(int signal)
{
	trace_terminate = 1;
}

static void read_trace_pipe(void)
{
	int fd;
	int orig_racount = racount;
	char buf[4096];
	char filename[4096];
	FILE *file;

	/* return readahead size to normal */
	readahead_set_len(RA_NORMAL);
	
	enter_debugfs();

	fd = open ("tracing/trace_pipe", O_RDONLY);
	fcntl (fd, F_SETFL, O_NONBLOCK);
	file = fdopen(fd, "r");
	if (!file) {
		perror("Unable to open trace file\n");
		exit(EXIT_FAILURE);
	}

	while (fgets(buf, 4095, file) != NULL) {
		char *start;
		char *len;

		if (buf[0] == '#')
			continue;

		start = strchr(buf, '"') + 1;
		if (start == buf)
			continue;

		len = strrchr(start, '"');
		strncpy(filename, start, len - start);

		filename[len - start] = '\0';

		/* ignore sys, dev, proc stuff */
		if (strncmp(filename, "/dev/", 5) == 0)
			continue;
		if (strncmp(filename, "/sys/", 5) == 0)
			continue;
		if (strncmp(filename, "/proc/", 6) == 0)
			continue;
		if (strncmp(filename, "/tmp/bootchart", 14) == 0)
			continue;

		if (racount >= MAXR) {
			perror("Max records exceeded!");
			break;
		}

		/* magic file; open me to abort sreadahead */
		if (strstr (filename, "sreadahead.complete.token")) {
			trace_terminate = 1;
			break;
		}

		if (strlen(filename) <= MAXFL) {
			struct ra_struct *tmp;
			tmp = malloc(sizeof(struct ra_struct));

			if (!tmp) {
				perror("Out of memory\n");
				exit(EXIT_FAILURE);
			}
			memset(tmp, 0, sizeof(struct ra_struct));

			ra[racount] = tmp;

			strcpy(ra[racount]->filename, filename);
			if (racount > 0) {
				ra[racount]->prev = ra[racount - 1];
				ra[racount - 1]->next = ra[racount];
			}
			ra[racount]->number = racount;
			racount++;
		}
	}
	fclose(file);

	if (debug)
		printf ("read %d records\n", racount - orig_racount);

	exit_debugfs();
}

static void trace_stop(void)
{
	FILE *file;
	struct ra_struct *r;
	struct tms start_time;
	struct tms stop_time;

	if (debug) {
		times(&start_time);
		printf("Trace contained %d records\n", racount);
	}

	enter_debugfs();

	/* stop tracing */
	trace_fprintf ("tracing/tracing_enabled", "0");
	trace_fprintf ("tracing/events/fs/do_sys_open/enable", "0");
	trace_fprintf ("tracing/events/fs/open_exec/enable", "0");
	trace_fprintf ("tracing/events/fs/uselib/enable", "0");

	exit_debugfs();

	first_ra = ra[0];

	/*
	 * sort and filter duplicates, and get memory blocks
	 */
	sort_ra_by_name();
	remove_dupes();
	get_ra_blocks();

	/*
	 * and write out the new pack file
	 */
	file = fopen(PACK_FILE, "w");
	if (!file) {
		perror("Unable to open output file\n");
		exit(EXIT_FAILURE);
	}

	if (!is_ssd)
		write_sorted_in_chunks_by_block (file, first_ra);
	else {
		for (r = first_ra; r; r = r->next)
			write_ra (file, r);
	}

	fclose(file);
	if (debug) {
		times(&stop_time);
		printf("Took %.3f seconds\n", (double)(stop_time.tms_utime -
		       start_time.tms_utime) / 1000.0f);
		printf("Total %d files, %dkb, %d fragments\n", rdcount,

		       rdsize / 1024, fcount);
	}

	exit(EXIT_SUCCESS);
}

static void print_usage(const char *name)
{
	printf("Usage: %s [OPTION...]\n", name);
	printf("  -t N, --time=N        Wait for N seconds before creating new\n");
	printf("                        pack file (default %d)\n", DEFAULT_MAX_TIME);
	printf("  -d,   --debug         Print debug output to stdout\n");
	printf("  -h,   --help          Show this help message\n");
	printf("  -v,   --version       Show version information and exit\n");
	exit(EXIT_SUCCESS);
}

static void print_version(void)
{
	printf("sreadahead version %s\n", VERSION);
	printf("Copyright (C) 2008, 2009 Intel Corporation\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	FILE *file;
	int i, max_threads;
	pthread_t threads[MAXTHREADS];
	int max_time = DEFAULT_MAX_TIME;

	kmsg_print ("sreadahead starting\n");

	while (1) {
		static struct option opts[] = {
			{ "debug", 0, NULL, 'd' },
			{ "help", 0, NULL, 'h' },
			{ "version", 0, NULL, 'v' },
			{ "time", 1, NULL, 't' },
			{ 0, 0, NULL, 0 }
		};
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "dhvt:", opts, &index);
		if (c == -1)
			break;
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'v':
			print_version();
			break;
		case 'h':
			print_usage(argv[0]);
			break;
		case 't':
			max_time = atoi(optarg);
			break;
		default:
			;
		}
	}

	is_ssd = is_sda_ssd ();
	if (!is_ssd)
		max_time *= 2;

	file = fopen(PACK_FILE, "r");
	if (!file) {
		/* enable tracing open calls before we fork! */
		trace_start();
	
		if (!fork()) {
			int i, max;
			max = max_time * 2;

			trace_terminate = 0;
			signal(SIGUSR1, trace_signal);


			/* It is important that we capture the mincore data
			   -before- we load more stuff, and push that out of
			   cache */
			nice(-10);

			for (i = 0; i < max && !trace_terminate; i++) {
			    usleep (1000000 / 2);
			    read_trace_pipe ();
			}
			/*
			 * abort if we don't get a signal, so we can stop
			 * the tracing and minimize the trace buffer size
			 */
			signal(SIGUSR1, NULL);
			trace_stop();
		} else {
			return EXIT_SUCCESS;
		}
	}

	total_files = fread(&rd, sizeof(struct ra_disk), MAXR, file);

	if (ferror(file)) {
		perror("Can't open sreadahead pack file");
		return 1;
	}
	fclose(file);


	if (is_ssd) {
		set_ioprio (IOPRIO_IDLE_LOWEST);	
		readahead_set_len(RA_SMALL);
		max_threads = 4;
	} else {
		set_ioprio (IOPRIO_RT_HIGHEST); /* will lower later */
		max_threads = 1;
	}

	daemon(0,0);

	for (i = 0; i < max_threads; i++)
		pthread_create(&threads[i], NULL, one_thread, NULL);

	for (i = 0; i < max_threads; i++)
		pthread_join(threads[i], NULL);

	if (is_ssd)
		readahead_set_len(RA_NORMAL);

	return EXIT_SUCCESS;
}
