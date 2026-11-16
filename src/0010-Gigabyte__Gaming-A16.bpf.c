// SPDX-License-Identifier: GPL-2.0-only
/* Fn key fix for the Gigabyte Aero X16 internal keyboard (0414:8104).
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_GIGABYTE	0x0414
#define PID_X16_KBD	0x8104

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_GIGABYTE, PID_X16_KBD)
);

/*
 * input0 (75 byte descriptor): boot keyboard, no Report ID (ID 0), 36 bytes:
 *   byte 0 modifiers, byte 1 reserved, bytes 2..7 a 6-key usage array,
 *   bytes 8..35 a bitmap of usages 0x00..0xdf.
 */
#define KBD_RDESC_SIZE		75
#define KBD_REPORT_SIZE		36
#define KBD_ARRAY_START		2
#define KBD_ARRAY_END		8
#define KBD_BITMAP_START	8

#define USAGE_P			0x13
#define USAGE_KP_EQUAL		0x67
#define USAGE_F13		0x68
#define USAGE_F14		0x69
#define USAGE_F15		0x6a
#define USAGE_F16		0x6b
#define USAGE_F17		0x6c
#define USAGE_FN		0x6f	/* F20 */
#define USAGE_LEFT_META		0xe3
#define USAGE_FIRST_MOD		0xe0

#define MISC_RDESC_SIZE		226
#define VENDOR_REPORT_ID	4
#define VENDOR_REPORT_SIZE	4
#define VENDOR_FN_F7		0x84
#define VENDOR_FN_F4		0x92
#define VENDOR_FN_G		0x93
#define RADIO_REPORT_ID		7
#define RADIO_REPORT_SIZE	2

#define EXTRA_REPORT_ID		0x10
#define EXTRA_MICMUTE		(1 << 0)
#define EXTRA_F14		(1 << 1)
#define EXTRA_F16		(1 << 2)
#define EXTRA_F17		(1 << 3)

static const __u8 extra_rdesc[] = {
	0x05, 0x01,		/* Usage Page (Generic Desktop) */
	0x09, 0x80,		/* Usage (System Control) */
	0xa1, 0x01,		/* Collection (Application) */
	0x85, EXTRA_REPORT_ID,	/*  Report ID (0x10) */
	0x15, 0x00,		/*  Logical Minimum (0) */
	0x25, 0x01,		/*  Logical Maximum (1) */
	0x75, 0x01,		/*  Report Size (1) */
	0x09, 0xa9,		/*  Usage (System Microphone Mute) */
	0x95, 0x01,		/*  Report Count (1) */
	0x81, 0x02,		/*  Input (Data,Var,Abs) */
	0x05, 0x07,		/*  Usage Page (Keyboard) */
	0x09, USAGE_F14,	/*  Usage (F14) */
	0x09, USAGE_F16,	/*  Usage (F16) */
	0x09, USAGE_F17,	/*  Usage (F17) */
	0x95, 0x03,		/*  Report Count (3) */
	0x81, 0x02,		/*  Input (Data,Var,Abs) */
	0x95, 0x04,		/*  Report Count (4) */
	0x81, 0x03,		/*  Input (Cnst,Var,Abs) */
	0xc0,			/* End Collection */
};

#define FIXED_MISC_RDESC_SIZE	(MISC_RDESC_SIZE + sizeof(extra_rdesc))

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(x16_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, HID_MAX_DESCRIPTOR_SIZE);

	if (!data)
		return 0; /* EPERM check */

	if (hctx->size != MISC_RDESC_SIZE || data[MISC_RDESC_SIZE - 1] != 0xc0)
		return 0;

	__builtin_memcpy(data + MISC_RDESC_SIZE, extra_rdesc, sizeof(extra_rdesc));

	return FIXED_MISC_RDESC_SIZE;
}

static void clear_array(__u8 *data)
{
	int i;

	for (i = KBD_ARRAY_START; i < KBD_ARRAY_END; i++)
		data[i] = 0x00;
}

static void fix_fn_macro(__u8 *data)
{
	bool has_key = false, has_p = false, has_meta = false;
	int i;

	for (i = KBD_ARRAY_START; i < KBD_ARRAY_END; i++) {
		if (data[i] == USAGE_P)
			has_p = true;
		else if (data[i] == USAGE_LEFT_META)
			has_meta = true;
		if (data[i] && data[i] < USAGE_FIRST_MOD)
			has_key = true;
	}

	if (!has_key) {
		clear_array(data);
	} else if (has_p && has_meta) {
		clear_array(data);
		data[KBD_ARRAY_START] = USAGE_F13;
	}
}

static int fix_keyboard_report(__u8 *data)
{
	bool fn = false;
	int i;

	for (i = KBD_ARRAY_START; i < KBD_ARRAY_END; i++) {
		if (data[i] == USAGE_FN) {
			data[i] = 0x00;
			fn = true;
		} else if (data[i] == USAGE_KP_EQUAL) {
			data[i] = USAGE_F15;
		}
	}
	data[KBD_BITMAP_START + USAGE_FN / 8] &= ~(1 << (USAGE_FN % 8));

	if (fn)
		fix_fn_macro(data);

	return 0;
}

static int send_extra_keys(struct hid_bpf_ctx *hctx, __u8 keys)
{
	__u8 report[2] = { EXTRA_REPORT_ID, keys };

	hid_bpf_try_input_report(hctx, HID_INPUT_REPORT, report, sizeof(report));
	report[1] = 0x00;
	hid_bpf_try_input_report(hctx, HID_INPUT_REPORT, report, sizeof(report));

	return -1;
}

static int fix_vendor_report(struct hid_bpf_ctx *hctx, __u8 *data)
{
	switch (data[3]) {
	case VENDOR_FN_F4:
		return send_extra_keys(hctx, EXTRA_MICMUTE);
	case VENDOR_FN_G:
		return send_extra_keys(hctx, EXTRA_F16);
	case VENDOR_FN_F7:
		return send_extra_keys(hctx, EXTRA_F17);
	}

	return 0;
}

static int fix_radio_report(struct hid_bpf_ctx *hctx, __u8 *data)
{
	if (!(data[1] & 0x01))
		return 0;

	return send_extra_keys(hctx, EXTRA_F14);
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(x16_device_event, struct hid_bpf_ctx *hctx)
{
	__u8 *data;

	switch (hctx->size) {
	case KBD_REPORT_SIZE:
		data = hid_bpf_get_data(hctx, 0, KBD_REPORT_SIZE);
		if (data)
			return fix_keyboard_report(data);
		break;
	case VENDOR_REPORT_SIZE:
		data = hid_bpf_get_data(hctx, 0, VENDOR_REPORT_SIZE);
		if (data && data[0] == VENDOR_REPORT_ID)
			return fix_vendor_report(hctx, data);
		break;
	case RADIO_REPORT_SIZE:
		data = hid_bpf_get_data(hctx, 0, RADIO_REPORT_SIZE);
		if (data && data[0] == RADIO_REPORT_ID)
			return fix_radio_report(hctx, data);
		break;
	}

	return 0;
}

HID_BPF_OPS(gigabyte_x16) = {
	.hid_device_event = (void *)x16_device_event,
	.hid_rdesc_fixup = (void *)x16_rdesc_fixup,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	switch (ctx->rdesc_size) {
	case KBD_RDESC_SIZE:
	case MISC_RDESC_SIZE:
	case FIXED_MISC_RDESC_SIZE:
		ctx->retval = 0;
		break;
	default:
		ctx->retval = -EINVAL;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
