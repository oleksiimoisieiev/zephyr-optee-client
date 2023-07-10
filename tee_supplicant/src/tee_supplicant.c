/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <stdio.h>
#include <zephyr/drivers/tee.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/posix/dirent.h>
#include <zephyr/posix/unistd.h>
#include <zephyr/sys/fdtable.h>

#include <optee_msg_supplicant.h>
#include <tee_client_api.h>
#include <teec_ta_load.h>

LOG_MODULE_REGISTER(tee_supplicant);

#define TEE_SUPP_THREAD_PRIO	7

#define TEE_REQ_PARAM_MAX	5

static struct k_thread main_thread;
static K_THREAD_STACK_DEFINE(main_stack, 8192);

static K_MUTEX_DEFINE(shm_mutex);

#define MEMREF_SHM_ID(p)	((p)->c)
#define MEMREF_SHM_OFFS(p)	((p)->a)
#define MEMREF_SIZE(p)		((p)->b)

struct tee_supp_request {
	uint32_t cmd;
	uint32_t num_param;
	struct tee_param params[TEE_REQ_PARAM_MAX];
};

struct tee_supp_response {
	uint32_t ret;
	uint32_t num_param;
	struct tee_param params[TEE_REQ_PARAM_MAX];
};

union tee_supp_msg {
	struct tee_supp_request req;
	struct tee_supp_response rsp;
};

struct param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

static int receive_request(const struct device *dev, struct tee_supp_request *ts_req)
{
	int rc = tee_suppl_recv(dev, &ts_req->cmd, &ts_req->num_param, ts_req->params);

	if (rc) {
		LOG_ERR("TEE supplicant receive failed, rc = %d", rc);
	}

	return rc;
}

static int send_response(const struct device *dev, struct tee_supp_response *rsp)
{
	int rc = tee_suppl_send(dev, rsp->ret, rsp->num_param, rsp->params);

	if (rc) {
		LOG_ERR("TEE supplicant send response failed, rc = %d", rc);
	}

	return rc;
}

static void uuid_from_octets(TEEC_UUID *d, const uint8_t s[TEE_UUID_LEN])
{
	d->timeLow = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
	d->timeMid = (s[4] << 8) | s[5];
	d->timeHiAndVersion = (s[6] << 8) | s[7];
	memcpy(d->clockSeqAndNode, s + 8, sizeof(d->clockSeqAndNode));
}

static int load_ta(uint32_t num_params, struct tee_param *params)
{
	int ta_found = 0;
	size_t size = 0;
	struct param_value *val_cmd = NULL;
	TEEC_UUID uuid = { 0 };
	struct tee_shm *shm;
	void *addr;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	printk("==== %s %d attr1 = %d attr2 = %d attr3 =%d\n", __func__, __LINE__,
	       params[0].attr, params[1].attr, params[2].attr);

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}
        printk("==== %s %d\n", __func__, __LINE__);

        shm = (struct tee_shm *)params[0].c;
        printk("==== %s %d\n", __func__, __LINE__);

        uuid_from_octets(&uuid, (uint8_t *)val_cmd);
        printk("==== %s %d\n", __func__, __LINE__);

        if (shm) {
		size = shm->size;
		addr = shm->addr;
	} else {
		size = 0;
		addr = NULL;
	}
        printk("==== %s %d\n", __func__, __LINE__);

        ta_found = TEECI_LoadSecureModule(&uuid, addr, &size);
	if (ta_found != TA_BINARY_FOUND) {
		LOG_ERR("TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}
        printk("==== %s %d\n", __func__, __LINE__);

        MEMREF_SIZE(params + 1) = size;

	/*
	 * If a buffer wasn't provided, just tell which size it should be.
	 * If it was provided but isn't big enough, report an error.
	 */
	if (addr && size > (shm? shm->size: 0)) {
		return TEEC_ERROR_SHORT_BUFFER;
	}
        printk("==== %s %d\n", __func__, __LINE__);

        return TEEC_SUCCESS;
}

static int tee_fs_open(size_t num_params, struct tee_param *params, int flags)
{
	struct tee_shm *shm;
	char *name, path[128 + 4] = "/tee";
	int fd;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, 128);
	fd = open(path, flags, 0600);
	if (fd < 0) {
		if (errno == ENOENT) {
			return TEEC_ERROR_ITEM_NOT_FOUND;
		}
		LOG_ERR("failed to open/create %s (%d)", path, -errno);
		return TEEC_ERROR_GENERIC;
	}

	params[2].a = fd;

	return TEEC_SUCCESS;
}

static int tee_fs_close(size_t num_params, struct tee_param *params)
{
	if (num_params != 1  || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (close((int)params[0].b) < 0) {
		LOG_ERR("failed to close file (%d)", -errno);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_read(size_t num_params, struct tee_param *params)
{
	int fd;
	off_t offset, position;
	size_t len, sz;
	struct tee_shm *shm;
	void *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	offset = params[0].c;

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;
	len = params[1].b;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	buf = shm->addr;
	position = lseek(fd, offset, SEEK_SET);
	if ((int)position < 0) {
		LOG_ERR("invalid offset %lu (%d)", offset, -errno);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*TODO: handle sz < len */
	sz = read(fd, buf, len);
	if ((int)sz < 0) {
		LOG_ERR("read failure (%d)", -errno);
		return TEEC_ERROR_GENERIC;
	}

	params[1].b = sz;
	return TEEC_SUCCESS;
}

static int tee_fs_write(size_t num_params, struct tee_param *params)
{
	int fd;
	off_t offset, position;
	size_t len, sz;
	struct tee_shm *shm;
	void *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	offset = params[0].c;

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;
	len = params[1].b;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	buf = shm->addr;
	position = lseek(fd, offset, SEEK_SET);
	if ((int)position < 0) {
		LOG_ERR("invalid offset %lu (%d)", offset, -errno);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	sz = write(fd, buf, len);
	if ((int)sz < 0) {
		/*TODO: handle error cases */
		LOG_ERR("write failure (%d)", -errno);
		return TEEC_ERROR_GENERIC;
	}

	params[1].b = sz;
	return TEEC_SUCCESS;
}

static int tee_fs_truncate(size_t num_params, struct tee_param *params)
{
	int rc, fd;
	off_t len;
	void *ptr = NULL;
	struct fs_file_t *file;

	if (num_params != 1  || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	len = params[0].c;
	ptr = z_get_fd_obj(fd, NULL, 0);

	if (!ptr) {
		LOG_ERR("descriptor %d not found", fd);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*HACK: this ptr is of hidden posix_fs_desc type, begins w/ file attr */
	file = (struct fs_file_t *)ptr;
	rc = fs_truncate(file, len);
	if (rc < 0) {
		LOG_ERR("failed to truncate (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_remove(size_t num_params, struct tee_param *params)
{
	struct tee_shm *shm;
	char *name, path[128 + 4] = "/tee";

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, 128);

	if (unlink(path) < 0) {
		if (errno == ENOENT) {
			return TEEC_ERROR_ITEM_NOT_FOUND;
		}
		LOG_ERR("failed to unlink %s (%d)", path, -errno);
		return TEEC_ERROR_GENERIC;
	}

	/*TODO: cleanup empty directories */
	return TEEC_SUCCESS;
}

static int tee_fs_rename(size_t num_params, struct tee_param *params)
{
	char *name, path[128 + 4] = "/tee";
	char *new_name, new_path[128 + 4] = "/tee";
	struct tee_shm *shm;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, 128);

	shm = (struct tee_shm *)params[2].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	new_name = shm->addr;
	strncat(new_path, new_name, 128);

	if (!params[0].b) {
		struct stat buf;
		if (stat(new_path, &buf) < 0) {
			return TEEC_ERROR_ACCESS_CONFLICT;
		}
	}

	if (rename(path, new_path) < 0) {
		LOG_ERR("failed to rename %s -> %s (%d)",
			path, new_path, -errno);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_opendir(size_t num_params, struct tee_param *params)
{
	struct tee_shm *shm;
	char *name, path[128 + 4] = "/tee";
	DIR *dirp;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, 128);
	dirp = opendir(path);
	if (!dirp) {
		LOG_ERR("failed to open %s (%d)", path, -errno);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	params[2].a =(uint64_t)dirp;

	return TEEC_SUCCESS;
}

static int tee_fs_closedir(size_t num_params, struct tee_param *params)
{
	DIR *dirp;

	if (num_params != 1  || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	dirp = (DIR *)params[0].b;
	if (!dirp) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (closedir(dirp) < 0) {
		LOG_ERR("closedir failed (%d)", -errno);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_readdir(size_t num_params, struct tee_param *params)
{
	struct tee_shm *shm;
	struct dirent *entry;
	DIR *dirp;
	size_t len;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	dirp = (DIR *)params[0].b;
	shm = (struct tee_shm *)params[1].c;

	if (!dirp || !shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (params[1].b != shm->size) {
		LOG_WRN("memref size not match shm size");
	}

	errno = 0;
	while (true) {
		entry = readdir(dirp);
		if (entry == NULL) {
			if (errno) {
				LOG_ERR("readdir failure (%d)", -errno);
			}
			return TEEC_ERROR_ITEM_NOT_FOUND;
		}

		if (entry->d_name[0] != '.') {
			break;
		}
	}

	len = strlen(entry->d_name) + 1;
	if (shm->size < len) {
		return TEEC_ERROR_SHORT_BUFFER;
	}

	memcpy(shm->addr, entry->d_name, len);
	return TEEC_SUCCESS;
}

static int tee_fs(uint32_t num_params, struct tee_param *params)
{
	unsigned mrf = -1;

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
		return tee_fs_open(num_params, params, O_RDWR);
	case OPTEE_MRF_CREATE:
		return tee_fs_open(num_params, params, O_RDWR | O_CREAT);
	case OPTEE_MRF_CLOSE:
		return tee_fs_close(num_params, params);
	case OPTEE_MRF_READ:
		return tee_fs_read(num_params, params);
	case OPTEE_MRF_WRITE:
		return tee_fs_write(num_params, params);
	case OPTEE_MRF_TRUNCATE:
		return tee_fs_truncate(num_params, params);
	case OPTEE_MRF_REMOVE:
		return tee_fs_remove(num_params, params);
	case OPTEE_MRF_RENAME:
		return tee_fs_rename(num_params, params);
	case OPTEE_MRF_OPENDIR:
		return tee_fs_opendir(num_params, params);
	case OPTEE_MRF_CLOSEDIR:
		return tee_fs_closedir(num_params, params);
	case OPTEE_MRF_READDIR:
		return tee_fs_readdir(num_params, params);
	};

	return TEEC_ERROR_BAD_PARAMETERS;
}

static int shm_alloc(const struct device *dev, uint32_t num_params,
		     struct tee_param *params)
{
	void *addr;
	size_t size;

	if (num_params != 1) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO: params[0].a is buffer type OPTEE_RPC_SHM_TYPE_*
	 * params[0].c is alignment
	*/
	switch (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) {
	case TEE_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_INOUT:
		size = params[0].b;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO: check for TEE_GEN_CAP_REG_MEM */
	addr = k_aligned_alloc(4096, size);
	if (!addr) {
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	params[0].c = (uint64_t)addr;

	return TEEC_SUCCESS;
}

static int shm_free(uint32_t num_params, struct tee_param *params)
{
	struct tee_shm *shm = NULL;

	if (num_params != 1) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	switch (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) {
	case TEE_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_INOUT:
		shm = (struct tee_shm*)params[0].b;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	k_free(shm->addr);
	return TEEC_SUCCESS;
}

static int process_request(const struct device *dev)
{
	int rc;
	union tee_supp_msg ts_msg = {
		.req.num_param = TEE_REQ_PARAM_MAX,
	};

	rc = receive_request(dev, &ts_msg.req);
	if (rc) {
		return rc;
	}

	LOG_ERR("Receive OPTEE request cmd #%d", ts_msg.req.cmd);
	switch (ts_msg.req.cmd) {
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		rc = load_ta(ts_msg.req.num_param, ts_msg.req.params);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		rc = tee_fs(ts_msg.req.num_param, ts_msg.req.params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		rc = shm_alloc(dev, ts_msg.req.num_param, ts_msg.req.params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		rc = shm_free(ts_msg.req.num_param, ts_msg.req.params);
		break;
	default:
		return TEEC_ERROR_NOT_SUPPORTED;
	}

	ts_msg.rsp.ret = rc;
	return send_response(dev, &ts_msg.rsp);
}

static void tee_supp_main(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	const struct device *dev = p1;
	int rc = 0;

	while (1) {
		rc = process_request(dev);
		if (rc) {
			LOG_ERR("Failed to process request, rc = %d", rc);
			break;
		}
	}
}

int tee_supp_init(const struct device *dev)
{
	const struct device *tee_dev = DEVICE_DT_GET_ONE(linaro_optee_tz);

	if (!tee_dev) {
		LOG_ERR("No TrustZone device found!");
		return -ENODEV;
	}

	k_thread_create(&main_thread, main_stack, K_THREAD_STACK_SIZEOF(main_stack), tee_supp_main,
			(void *) tee_dev, NULL, NULL, TEE_SUPP_THREAD_PRIO, 0, K_NO_WAIT);

	LOG_INF("Started tee_supplicant thread");
	return 0;
}

SYS_INIT(tee_supp_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
