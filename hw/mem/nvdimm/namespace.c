/*
 * NVDIMM  Namespace Support
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *  Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *
 * NVDIMM namespace specification can be found at:
 *      http://pmem.io/documents/NVDIMM_Namespace_Spec.pdf
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include "hw/mem/nvdimm.h"
#include "internal.h"

static uint64_t fletcher64(void *addr, size_t len)
{
    uint32_t *buf = addr;
    uint32_t lo32 = 0;
    uint64_t hi32 = 0;
    int i;

    for (i = 0; i < len / sizeof(uint32_t); i++) {
        lo32 += cpu_to_le32(buf[i]);
        hi32 += lo32;
    }

    return hi32 << 32 | lo32;
}

struct interleave_set_info {
    struct interleave_set_info_map {
        uint64_t region_spa_offset;
        uint32_t serial_number;
        uint32_t zero;
    } mapping[1];
};
typedef struct interleave_set_info interleave_set_info;

void calculate_nvdimm_isetcookie(NVDIMMDevice *nvdimm, uint64_t spa_offset,
                                 uint32_t sn)
{
    interleave_set_info info;

    info.mapping[0].region_spa_offset = spa_offset;
    info.mapping[0].serial_number = sn;
    info.mapping[0].zero = 0;

    nvdimm->isetcookie = fletcher64(&info, sizeof(info));
}

#define NSINDEX_SIGNATURE      "NAMESPACE_INDEX\0"

enum {
    NSINDEX_SIG_LEN = 16,
    NSINDEX_ALIGN = 256,
    NSINDEX_SEQ_MASK = 0x3,
    NSINDEX_MAJOR = 0x1,
    NSINDEX_MINOR = 0x1,

    NSLABEL_UUID_LEN = 16,
    NSLABEL_NAME_LEN = 64,
    NSLABEL_FLAG_ROLABEL = 0x1,  /* read-only label */
    NSLABEL_FLAG_LOCAL = 0x2,    /* DIMM-local namespace */
    NSLABEL_FLAG_BTT = 0x4,      /* namespace contains a BTT */
    NSLABEL_FLAG_UPDATING = 0x8, /* label being updated */
};

/*
 * struct nd_namespace_index - label set superblock
 * @sig: NAMESPACE_INDEX\0
 * @flags: placeholder
 * @seq: sequence number for this index
 * @myoff: offset of this index in label area
 * @mysize: size of this index struct
 * @otheroff: offset of other index
 * @labeloff: offset of first label slot
 * @nslot: total number of label slots
 * @major: label area major version
 * @minor: label area minor version
 * @checksum: fletcher64 of all fields
 * @free[0]: bitmap, nlabel bits
 *
 * The size of free[] is rounded up so the total struct size is a
 * multiple of NSINDEX_ALIGN bytes.  Any bits this allocates beyond
 * nlabel bits must be zero.
 */
struct namespace_label_index_block {
    uint8_t sig[NSINDEX_SIG_LEN];
    uint32_t flags;
    uint32_t seq;
    uint64_t myoff;
    uint64_t mysize;
    uint64_t otheroff;
    uint64_t labeloff;
    uint32_t nlabel;
    uint16_t major;
    uint16_t minor;
    uint64_t checksum;
    uint8_t free[0];
} QEMU_PACKED;
typedef struct namespace_label_index_block namespace_label_index_block;

/*
 * struct nd_namespace_label - namespace superblock
 * @uuid: UUID per RFC 4122
 * @name: optional name (NULL-terminated)
 * @flags: see NSLABEL_FLAG_*
 * @nlabel: num labels to describe this ns
 * @position: labels position in set
 * @isetcookie: interleave set cookie
 * @lbasize: LBA size in bytes or 0 for pmem
 * @dpa: DPA of NVM range on this DIMM
 * @rawsize: size of namespace
 * @slot: slot of this label in label area
 * @unused: must be zero
 */
struct namespace_label {
    uint8_t uuid[NSLABEL_UUID_LEN];
    uint8_t name[NSLABEL_NAME_LEN];
    uint32_t flags;
    uint16_t nlabel;
    uint16_t position;
    uint64_t isetcookie;
    uint64_t lbasize;
    uint64_t dpa;
    uint64_t rawsize;
    uint32_t slot;
    uint32_t unused;
} QEMU_PACKED;
typedef struct namespace_label namespace_label;

/*calculate the number of label can be contained in whole label data. */
static int label_data_max_label_nr(NVDIMMDevice *nvdimm, size_t block_size)
{
    /* totally we have 2 namespace label index block. */
    if (block_size * 2 >= nvdimm->label_size) {
        return 0;
    }

    return (nvdimm->label_size - block_size * 2) / sizeof(namespace_label);
}

/*calculate the number of label can be contained in index block. */
static int label_index_block_max_label_nr(size_t block_size)
{
    int free_size;

    free_size = block_size - sizeof(namespace_label_index_block);

    return free_size * BITS_PER_BYTE;
}

static int calculate_max_label_nr(NVDIMMDevice *nvdimm, size_t block_size)
{
    return MIN(label_index_block_max_label_nr(block_size),
        label_data_max_label_nr(nvdimm, block_size));
}

/*
 * check if we can increase the size of namespace_label_index_block to
 * contain more labels.
 */
static bool can_increase_index_block(NVDIMMDevice *nvdimm,
                                     size_t block_size, int label_nr)
{
    size_t remaining;

    remaining = nvdimm->label_size - block_size * 2 -
                label_nr * sizeof(namespace_label);

    assert((int64_t)remaining >= 0);

    /* can contain 1 label at least. */
    return remaining >=  NSINDEX_ALIGN * 2 + sizeof(namespace_label);
}

static void count_label_nr(NVDIMMDevice *nvdimm, size_t *label_block_size,
                           int *label_nr)
{
    *label_block_size = 0;

    do {
        /*
          * The minimum size of an index block is 256 bytes and the size must
          * be a multiple of 256 bytes.
          */
        *label_block_size += NSINDEX_ALIGN;

        *label_nr = calculate_max_label_nr(nvdimm, *label_block_size);
    } while (can_increase_index_block(nvdimm, *label_block_size, *label_nr));
}

static void namespace_label_uuid(NVDIMMDevice *nvdimm, void *uuid)
{
    /* magic UUID. */
    uuid_le label_uuid_init = UUID_LE(0x137e67a9, 0x7dcb, 0x4c66, 0xb2,
                                      0xe6, 0x05, 0x06, 0x5b, 0xeb,
                                      0x6a, 0x00);
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP, NULL);

    label_uuid_init.b[0] += slot;
    memcpy(uuid, &label_uuid_init, sizeof(label_uuid_init));
}

static void nvdimm_device_init_namespace(NVDIMMDevice *nvdimm)
{
    namespace_label_index_block *index1, *index2;
    namespace_label *label;
    uint64_t addr = object_property_get_int(OBJECT(nvdimm), DIMM_ADDR_PROP,
                                            NULL);
    uint64_t size = object_property_get_int(OBJECT(nvdimm), DIMM_SIZE_PROP,
                                            NULL);
    int slot = object_property_get_int(OBJECT(nvdimm), DIMM_SLOT_PROP, NULL);
    int i, label_nr;
    size_t label_block_size;

    nvdimm->label_data = g_malloc(nvdimm->label_size);

    count_label_nr(nvdimm, &label_block_size, &label_nr);
    nvdebug("nvdimm%d: label_block_size 0x%lx label_nr %d.\n",
            slot, label_block_size, label_nr);

    index1 = nvdimm->label_data;

    /*
     * init the first namespace label index block, except @otheroff
     * and @checksum. we will do it later.
     */
    memcpy(index1->sig, NSINDEX_SIGNATURE, sizeof(NSINDEX_SIGNATURE));
    index1->flags = cpu_to_le32(0);
    index1->seq = cpu_to_le32(0x1);
    index1->myoff = cpu_to_le64(0);
    index1->mysize = cpu_to_le64(label_block_size);
    index1->labeloff = cpu_to_le64(label_block_size * 2);
    index1->nlabel = cpu_to_le32(label_nr);
    index1->major = cpu_to_le16(NSINDEX_MAJOR);
    index1->minor = cpu_to_le16(NSINDEX_MINOR);
    index1->checksum = cpu_to_le64(0);
    memset(index1->free, 0,
           label_block_size - sizeof(namespace_label_index_block));

    /*
     * the label slot with the lowest offset in the label storage area is
     * tracked by the least significant bit of the first byte of the free
     * array.
     *
     * the fist label is used.
     */
    for (i = 1; i < index1->nlabel; i++) {
        set_bit(i, (unsigned long *)index1->free);
    }

    /* init the second namespace label index block. */
    index2 = (void *)index1 + label_block_size;
    memcpy(index2, index1, label_block_size);
    index2->seq = cpu_to_le32(0x2);
    index2->myoff = cpu_to_le64(label_block_size);

    /* init @otheroff and @checksume. */
    index1->otheroff = cpu_to_le64(index2->myoff);
    index2->otheroff = cpu_to_le64(index1->myoff);
    index1->checksum = cpu_to_le64(fletcher64(index1, label_block_size));
    index2->checksum = cpu_to_le64(fletcher64(index2, label_block_size));

    /* only one label is used which is the first label and is readonly. */
    label = nvdimm->label_data + label_block_size * 2;
    namespace_label_uuid(nvdimm, label->uuid);
    sprintf((char *)label->name, "QEMU NS%d", slot);
    label->flags = cpu_to_le32(NSLABEL_FLAG_ROLABEL);
    label->nlabel = cpu_to_le16(1);
    label->position = cpu_to_le16(0);
    label->isetcookie = cpu_to_le64(nvdimm->isetcookie);
    label->lbasize = cpu_to_le64(0);
    label->dpa = cpu_to_le64(addr);
    label->rawsize = cpu_to_le64(size);
    label->slot = cpu_to_le32(0);
    label->unused = cpu_to_le32(0);

    nvdebug("nvdimm%d, checksum1 0x%lx checksum2 0x%lx isetcookie 0x%lx.\n",
            slot, index1->checksum, index2->checksum,
            label->isetcookie);
}

void build_nvdimm_label_data(GSList *device_list)
{
    for (; device_list; device_list = device_list->next) {
        NVDIMMDevice *nvdimm = device_list->data;

        if (nvdimm->label_data) {
            continue;
        }

        nvdimm_device_init_namespace(nvdimm);
    }
}
