/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/drivers/tee.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

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

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT)
	{
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	shm = (struct tee_shm *)params[0].c;

	uuid_from_octets(&uuid, (uint8_t *)val_cmd);

	if (shm) {
		size = shm->size;
		addr = shm->addr;
	} else {
		size = 0;
		addr = NULL;
	}

	ta_found = TEECI_LoadSecureModule(&uuid, addr, &size);
	if (ta_found != TA_BINARY_FOUND) {
		LOG_ERR("TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	MEMREF_SIZE(params + 1) = size;

	/*
	 * If a buffer wasn't provided, just tell which size it should be.
	 * If it was provided but isn't big enough, report an error.
	 */
	if (addr && size > (shm? shm->size: 0)) {
		return TEEC_ERROR_SHORT_BUFFER;
	}

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

	LOG_DBG("Receive OPTEE request cmd #%d", ts_msg.req.cmd);
	switch (ts_msg.req.cmd) {
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		rc = load_ta(ts_msg.req.num_param, ts_msg.req.params);
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
