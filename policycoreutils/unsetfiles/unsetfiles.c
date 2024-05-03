#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <selinux/selinux.h>


#define XATTR_NAME_SELINUX "security.selinux"


static void usage(const char *progname)
{
	fprintf(stderr, "usage: %s [-nrvx] <path>\n\n"
	                "Options:\n"
	                "\t-n\tdon't remove any file labels\n"
	                "\t-r\tremove labels recursive\n"
	                "\t-v\tbe verbose\n"
	                "\t-x\tdo not cross filesystem boundaries\n",
	                progname);
}

static void unset(int atfd, const char *path, const char *fullpath,
                  bool dry_run, bool recursive, bool verbose,
                  dev_t root_dev)
{
	ssize_t ret;
	int fd, rc;
	DIR *dir;

	ret = lgetxattr(fullpath, XATTR_NAME_SELINUX, NULL, 0);
	if (ret <= 0) {
		if (errno != ENODATA && errno != ENOTSUP)
			fprintf(stderr, "Failed to get SELinux label of %s:  %m\n", fullpath);
		else if (verbose)
			printf("Failed to get SELinux label of %s:  %m\n", fullpath);
	} else {
		if (dry_run) {
			printf("Would remove SELinux label of %s\n", fullpath);
		} else {
			if (verbose)
				printf("Removing label of %s\n", fullpath);

			rc = lremovexattr(fullpath, XATTR_NAME_SELINUX);
			if (rc < 0)
				fprintf(stderr, "Failed to remove SELinux label of %s:  %m\n", fullpath);
		}
	}

	if (!recursive)
		return;

	fd = openat(atfd, path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOTDIR)
			fprintf(stderr, "Failed to open %s:  %m\n", fullpath);
		return;
	}

	if (root_dev != (dev_t)-1) {
		struct stat sb;

		rc = fstat(fd, &sb);
		if (rc == -1) {
			fprintf(stderr, "Failed to stat directory %s:  %m\n", fullpath);
			close(fd);
			return;
		}

		if (sb.st_dev != root_dev) {
			if (verbose)
				printf("Skipping directory %s due to filesystem boundary\n", fullpath);

			close(fd);
			return;
		}
	}

	dir = fdopendir(fd);
	if (!dir) {
		fprintf(stderr, "Failed to open directory %s:  %m\n", fullpath);
		close(fd);
		return;
	}

	while (true) {
		const struct dirent *entry;
		char *nextfullpath;

		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			if (errno)
				fprintf(stderr, "Failed to iterate directory %s:  %m\n", fullpath);
			break;
		}

		if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
			continue;

		rc = asprintf(&nextfullpath, "%s/%s", strcmp(fullpath, "/") == 0 ? "" : fullpath, entry->d_name);
		if (rc < 0) {
			fprintf(stderr, "Out of memory!\n");
			closedir(dir);
			return;
		}

		unset(dirfd(dir), entry->d_name, nextfullpath, dry_run, recursive, verbose, root_dev);

		free(nextfullpath);
	}

	closedir(dir);
}


int main(int argc, char *argv[])
{
	bool dry_run = false, recursive = false, verbose = false, same_dev = false;
	int c;

	while ((c = getopt(argc, argv, "hnrvx")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'n':
			dry_run = true;
			break;
		case 'r':
			recursive = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'x':
			same_dev = true;
			break;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (is_selinux_enabled()) {
		fprintf(stderr, "Removing SELinux attributes on a SELinux enabled system is not supported!\n");
		return EXIT_FAILURE;
	}

	for (int index = optind; index < argc; index++) {
		dev_t root_dev = (dev_t)-1;

		if (same_dev) {
			struct stat sb;
			int rc;

			rc = stat(argv[index], &sb);
			if (rc == -1) {
				fprintf(stderr, "Failed to stat %s:  %m\n", argv[index]);
				continue;
			}

			root_dev = sb.st_dev;
		}
		unset(AT_FDCWD, argv[index], argv[index], dry_run, recursive, verbose, root_dev);
	}

	return EXIT_SUCCESS;
}
