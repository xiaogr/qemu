/*
 * Non-Volatile Dual In-line Memory Module Virtualization Implementation
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *  Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef NVDIMM_INTERNAL_H
#define NVDIMM_INTERNAL_H

#define MIN_NAMESPACE_LABEL_SIZE    (128UL << 10)

struct uuid_le {
    uint8_t b[16];
};
typedef struct uuid_le uuid_le;

#define UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)                   \
((uuid_le)                                                                 \
{ { (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
    (b) & 0xff, ((b) >> 8) & 0xff, (c) & 0xff, ((c) >> 8) & 0xff,          \
    (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } })

GSList *nvdimm_get_built_list(void);
#endif
