/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 EPAM Systems
 *
 */
#pragma once
#include <tee_client_api.h>

struct thread_arg;

int tee_fs(struct thread_arg *arg, uint32_t num_params, struct tee_param *params);
