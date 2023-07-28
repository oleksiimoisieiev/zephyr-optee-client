// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 *
 */


#include <optee_msg_supplicant.h>
#include <ree_fs.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/fdtable.h>
#include "tee_supplicant.h"

LOG_MODULE_REGISTER(ree_fs);

static int internal_open(char *path, fs_mode_t flags)
{
	int fd, rc;
	struct fs_file_t *file;

	file = k_malloc(sizeof(*file));
	if (!file) {
		return -ENOMEM;
	}

	fs_file_t_init(file);
	fd = z_alloc_fd(file, NULL);
	if (fd < 0) {
		rc = TEEC_ERROR_GENERIC;
		goto free;
	}

	rc = fs_open(file, path, flags);
	if (rc < 0) {
		goto free;
	}
	return fd;
free:
	if (fd >= 0) {
		z_free_fd(fd);
	}
	k_free(file);
	return rc;
}

static char *dname(char *path)
{
	char *slash;

	slash = strrchr(path, '/');
	if (slash != NULL) {
		if (slash[1] == 0 && slash != path) {
			*slash-- = 0;
			slash = strrchr(path, '/');
		}
		if (slash != NULL && slash != path) {
			*slash = 0;
			return path;
		}
	}
	return NULL;
}

static int tee_fs_open(struct thread_arg *arg, size_t num_params, struct tee_param *params,
		       fs_mode_t flags)
{
	char *name, path[PATH_MAX];
	int fd, rc = TEEC_SUCCESS;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	strcpy(path, arg->tee_fs_root);
	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	strncat(path, name, PATH_MAX);

	fd = internal_open(path, flags);
	if (fd < 0) {
		if (flags & FS_O_CREATE) {
			char *dir;

			dir = dname(path);
			if (!dir) {
				rc = TEEC_ERROR_GENERIC;
				goto out;
			}
			rc = fs_mkdir(dir);
			if (rc < 0) {
				rc = TEEC_ERROR_GENERIC;
				goto out;
			}
			strcpy(path, arg->tee_fs_root);
			strncat(path, name, PATH_MAX);
			fd = internal_open(path, flags);
			if (fd < 0) {
				if (rc == -ENOENT) {
					rc = TEEC_ERROR_ITEM_NOT_FOUND;
					goto out;
				}
				LOG_ERR("failed to create '%s' (%d)", path, rc);
				rc = TEEC_ERROR_GENERIC;
				goto out;
			}
		} else {
			if (fd == -ENOENT) {
				rc = TEEC_ERROR_ITEM_NOT_FOUND;
				goto out;
			}
			LOG_ERR("failed to open '%s' (%d)", path, rc);
			rc = TEEC_ERROR_GENERIC;
			goto out;
		}
	}

	params[2].a = fd;
out:
	return rc;
}

static int tee_fs_close(size_t num_params, struct tee_param *params)
{
	int fd, rc;
	struct fs_file_t *file;

	if (num_params != 1 || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		LOG_ERR("fd %d not found", fd);
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	rc = fs_close(file);
	z_free_fd(fd);
	k_free(file);

	if (rc < 0) {
		LOG_ERR("failed to close file (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_read(size_t num_params, struct tee_param *params)
{
	int fd, rc;
	off_t offset;
	size_t len;
	ssize_t sz;
	struct fs_file_t *file;
	void *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	offset = params[0].c;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	buf = tee_param_get_mem(params + 1, NULL);
	if (!buf) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	len = MEMREF_SIZE(params + 1);
	rc = fs_seek(file, offset, SEEK_SET);
	if (rc < 0) {
		LOG_ERR("invalid offset %ld (%d)", offset, rc);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*TODO: handle sz < len */
	sz = fs_read(file, buf, len);
	if (sz < 0) {
		LOG_ERR("read failure (%ld)", sz);
		return TEEC_ERROR_GENERIC;
	}

	SET_MEMREF_SIZE(params + 1, sz);
	return TEEC_SUCCESS;
}

static int tee_fs_write(size_t num_params, struct tee_param *params)
{
	int fd, rc;
	off_t offset;
	size_t len;
	ssize_t sz;
	struct fs_file_t *file;
	void *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	offset = params[0].c;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	buf = tee_param_get_mem(params + 1, NULL);
	if (!buf) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	len = MEMREF_SIZE(params + 1);
	rc = fs_seek(file, offset, SEEK_SET);
	if (rc < 0) {
		LOG_ERR("invalid offset %ld (%d)", offset, rc);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*TODO: handle case of partially written buffer */
	sz = fs_write(file, buf, len);
	if (sz < 0) {
		LOG_ERR("write failure (%ld)", sz);
		return TEEC_ERROR_GENERIC;
	}

	SET_MEMREF_SIZE(params + 1, sz);
	return TEEC_SUCCESS;
}

static int tee_fs_truncate(size_t num_params, struct tee_param *params)
{
	int rc, fd;
	off_t len;
	struct fs_file_t *file;

	if (num_params != 1 || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	len = params[0].c;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	rc = fs_truncate(file, len);
	if (rc < 0) {
		LOG_ERR("failed to truncate (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_remove(struct thread_arg *arg, size_t num_params, struct tee_param *params)
{
	char *name, path[PATH_MAX];
	int rc;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	strcpy(path, arg->tee_fs_root);
	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	strncat(path, name, PATH_MAX);

	rc = fs_unlink(path);
	if (rc < 0) {
		if (rc == -ENOENT) {
			return TEEC_ERROR_ITEM_NOT_FOUND;
		}
		LOG_ERR("failed to unlink %s (%d)", path, rc);
		return TEEC_ERROR_GENERIC;
	}

	while (1) {
		struct fs_dir_t dir;
		struct fs_dirent entry;
		char *dirname = path + strlen(arg->tee_fs_root);

		if (!dname(dirname)) {
			break;
		}
		fs_dir_t_init(&dir);
		rc = fs_opendir(&dir, path);
		if (rc < 0) {
			LOG_ERR("failed to open %s (%d)", path, rc);
			return -ENOENT;
		}
		rc = fs_readdir(&dir, &entry);
		fs_closedir(&dir);
		if (rc < 0) {
			return rc;
		}
		if (entry.name[0]) {
			break;
		}
		rc = fs_unlink(path);
		if (rc < 0) {
			return rc;
		}
	}
	return TEEC_SUCCESS;
}

static int tee_fs_rename(struct thread_arg *arg, size_t num_params, struct tee_param *params)
{
	char *name, path[PATH_MAX];
	char *new_name, new_path[PATH_MAX];
	int rc;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	strcpy(path, arg->tee_fs_root);
	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	strncat(path, name, PATH_MAX);

	strcpy(new_path, arg->tee_fs_root);
	new_name = tee_param_get_mem(params + 2, NULL);
	if (!new_name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	strncat(new_path, new_name, PATH_MAX);

	/* overwrite flag */
	if (!params[0].b) {
		struct fs_statvfs buf;

		if (!fs_statvfs(new_path, &buf)) {
			return TEEC_ERROR_ACCESS_CONFLICT;
		}
	}

	rc = fs_rename(path, new_path);
	if (rc < 0) {
		LOG_ERR("failed to rename %s -> %s (%d)",
			path, new_path, rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_opendir(struct thread_arg *arg, size_t num_params, struct tee_param *params)
{
	char *name, path[PATH_MAX];
	struct fs_dir_t *dir;
	int rc;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	strcpy(path, arg->tee_fs_root);
	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	strncat(path, name, PATH_MAX);

	dir = k_malloc(sizeof(*dir));
	if (!dir) {
		return TEEC_ERROR_GENERIC;
	}

	fs_dir_t_init(dir);
	rc = fs_opendir(dir, path);
	if (rc < 0) {
		LOG_ERR("failed to open %s (%d)", path, rc);
		k_free(dir);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	params[2].a = (uint64_t)dir;

	return TEEC_SUCCESS;
}

static int tee_fs_closedir(size_t num_params, struct tee_param *params)
{
	struct fs_dir_t *dir;
	int rc;

	if (num_params != 1 || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	dir = (struct fs_dir_t *)params[0].b;
	if (!dir) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	rc = fs_closedir(dir);
	k_free(dir);

	if (rc < 0) {
		LOG_ERR("closedir failed (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_readdir(size_t num_params, struct tee_param *params)
{
	struct fs_dirent entry;
	struct fs_dir_t *dir;
	size_t len, size;
	int rc;
	char *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	dir = (struct fs_dir_t *)params[0].b;
	buf = tee_param_get_mem(params + 1, &size);
	if (!dir || !buf) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (params[1].b != size) {
		LOG_WRN("memref size not match shm size");
	}

	rc = fs_readdir(dir, &entry);
	if (rc < 0) {
		LOG_ERR("readdir failure (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	if (entry.name[0] == 0) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	len = strlen(entry.name) + 1;
	if (size < len) {
		return TEEC_ERROR_SHORT_BUFFER;
	}

	memcpy(buf, entry.name, len);
	return TEEC_SUCCESS;
}

int tee_fs(struct thread_arg *arg, uint32_t num_params, struct tee_param *params)
{
	unsigned int mrf = -1;

	switch (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) {
	case TEE_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_INOUT:
		mrf = params[0].a;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	switch (mrf) {
	case OPTEE_MRF_OPEN:
		return tee_fs_open(arg, num_params, params, FS_O_RDWR);
	case OPTEE_MRF_CREATE:
		return tee_fs_open(arg, num_params, params, FS_O_RDWR | FS_O_CREATE);
	case OPTEE_MRF_CLOSE:
		return tee_fs_close(num_params, params);
	case OPTEE_MRF_READ:
		return tee_fs_read(num_params, params);
	case OPTEE_MRF_WRITE:
		return tee_fs_write(num_params, params);
	case OPTEE_MRF_TRUNCATE:
		return tee_fs_truncate(num_params, params);
	case OPTEE_MRF_REMOVE:
		return tee_fs_remove(arg, num_params, params);
	case OPTEE_MRF_RENAME:
		return tee_fs_rename(arg, num_params, params);
	case OPTEE_MRF_OPENDIR:
		return tee_fs_opendir(arg, num_params, params);
	case OPTEE_MRF_CLOSEDIR:
		return tee_fs_closedir(num_params, params);
	case OPTEE_MRF_READDIR:
		return tee_fs_readdir(num_params, params);
	};

	return TEEC_ERROR_BAD_PARAMETERS;
}
