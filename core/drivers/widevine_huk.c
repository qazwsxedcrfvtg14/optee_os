// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, The ChromiumOS Authors
 */

#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static uint8_t dt_huk[HW_UNIQUE_KEY_LENGTH];
static bool dt_huk_initialized = false;

static TEE_Result init_widevine_huk_dt_data(void)
{
	int node = 0;
	int len = 0;
	void *fdt = NULL;
	const void *value = NULL;

	if (dt_huk_initialized)
		return TEE_SUCCESS;

	fdt = get_dt();
	if (!fdt)
		return TEE_ERROR_NO_DATA;

	node = fdt_path_offset(fdt, "/options/widevine");
	if (node < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	value = fdt_getprop(fdt, node, "optee-hardware-unique-key", &len);
	if (!value)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len >= HW_UNIQUE_KEY_LENGTH)
		len = HW_UNIQUE_KEY_LENGTH;
	else
		return TEE_ERROR_BAD_FORMAT;

	dt_huk_initialized = true;

	return TEE_SUCCESS;
}

service_init(init_widevine_huk_dt_data);

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result result;

	result = init_widevine_huk_dt_data();
	if (result != TEE_SUCCESS)
		return result;

	memcpy(hwkey->data, dt_huk, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}
