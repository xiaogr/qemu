/*
 * QTest testcase for the vhost-user
 *
 * Copyright (c) 2014 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <glib.h>

#include "libqtest.h"
#include "qemu/option.h"
#include "sysemu/char.h"
#include "sysemu/sysemu.h"

#include <linux/vhost.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <qemu/sockets.h>

/* GLIB version compatibility flags */
#if !GLIB_CHECK_VERSION(2, 26, 0)
#define G_TIME_SPAN_SECOND              (G_GINT64_CONSTANT(1000000))
#endif

#if GLIB_CHECK_VERSION(2, 28, 0)
#define HAVE_MONOTONIC_TIME
#endif

#define QEMU_CMD_ACCEL  " -machine accel=tcg"
#define QEMU_CMD_MEM    " -m 512 -object memory-backend-file,id=mem,size=512M,"\
                        "mem-path=%s,share=on -numa node,memdev=mem"
#define QEMU_CMD_CHR    " -chardev socket,id=chr0,path=%s"
#define QEMU_CMD_NETDEV " -netdev vhost-user,id=net0,chardev=chr0,vhostforce"
#define QEMU_CMD_NET    " -device virtio-net-pci,netdev=net0 "
#define QEMU_CMD_ROM    " -option-rom ../pc-bios/pxe-virtio.rom"

#define QEMU_CMD        QEMU_CMD_ACCEL QEMU_CMD_MEM QEMU_CMD_CHR \
                        QEMU_CMD_NETDEV QEMU_CMD_NET QEMU_CMD_ROM

#define HUGETLBFS_MAGIC       0x958458f6

/*********** FROM hw/virtio/vhost-user.c *************************************/

#define VHOST_MEMORY_MAX_NREGIONS    8

#define VHOST_USER_F_PROTOCOL_FEATURES 30

typedef enum VhostUserRequest {
    VHOST_USER_NONE = 0,
    VHOST_USER_GET_FEATURES = 1,
    VHOST_USER_SET_FEATURES = 2,
    VHOST_USER_SET_OWNER = 3,
    VHOST_USER_RESET_DEVICE = 4,
    VHOST_USER_SET_MEM_TABLE = 5,
    VHOST_USER_SET_LOG_BASE = 6,
    VHOST_USER_SET_LOG_FD = 7,
    VHOST_USER_SET_VRING_NUM = 8,
    VHOST_USER_SET_VRING_ADDR = 9,
    VHOST_USER_SET_VRING_BASE = 10,
    VHOST_USER_GET_VRING_BASE = 11,
    VHOST_USER_SET_VRING_KICK = 12,
    VHOST_USER_SET_VRING_CALL = 13,
    VHOST_USER_SET_VRING_ERR = 14,
    VHOST_USER_GET_PROTOCOL_FEATURES = 15,
    VHOST_USER_SET_PROTOCOL_FEATURES = 16,
    VHOST_USER_MAX
} VhostUserRequest;

typedef struct VhostUserMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t mmap_offset;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
    uint32_t nregions;
    uint32_t padding;
    VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserMsg {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK     (0x3)
#define VHOST_USER_REPLY_MASK       (0x1<<2)
    uint32_t flags;
    uint32_t size; /* the following payload size */
    union {
        uint64_t u64;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        VhostUserMemory memory;
    };
} QEMU_PACKED VhostUserMsg;

static VhostUserMsg m __attribute__ ((unused));
#define VHOST_USER_HDR_SIZE (sizeof(m.request) \
                            + sizeof(m.flags) \
                            + sizeof(m.size))

#define VHOST_USER_PAYLOAD_SIZE (sizeof(m) - VHOST_USER_HDR_SIZE)

/* The version of the protocol we support */
#define VHOST_USER_VERSION    (0x1)
/*****************************************************************************/

int fds_num = 0, fds[VHOST_MEMORY_MAX_NREGIONS];
static VhostUserMemory memory;
static CompatGMutex data_mutex;
static CompatGCond data_cond;

#if !GLIB_CHECK_VERSION(2, 32, 0)
static gboolean g_cond_wait_until(CompatGCond cond, CompatGMutex mutex,
                                  gint64 end_time)
{
    gboolean ret = FALSE;
    end_time -= g_get_monotonic_time();
    GTimeVal time = { end_time / G_TIME_SPAN_SECOND,
                      end_time % G_TIME_SPAN_SECOND };
    ret = g_cond_timed_wait(cond, mutex, &time);
    return ret;
}
#endif

static void wait_for_fds(void)
{
    gint64 end_time;

    g_mutex_lock(&data_mutex);

    end_time = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (!fds_num) {
        if (!g_cond_wait_until(&data_cond, &data_mutex, end_time)) {
            /* timeout has passed */
            g_assert(fds_num);
            break;
        }
    }

    /* check for sanity */
    g_assert_cmpint(fds_num, >, 0);
    g_assert_cmpint(fds_num, ==, memory.nregions);

    g_mutex_unlock(&data_mutex);
}

static void read_guest_mem(void)
{
    uint32_t *guest_mem;
    int i, j;
    size_t size;

    wait_for_fds();

    g_mutex_lock(&data_mutex);

    /* iterate all regions */
    for (i = 0; i < fds_num; i++) {

        /* We'll check only the region statring at 0x0*/
        if (memory.regions[i].guest_phys_addr != 0x0) {
            continue;
        }

        g_assert_cmpint(memory.regions[i].memory_size, >, 1024);

        size =  memory.regions[i].memory_size + memory.regions[i].mmap_offset;

        guest_mem = mmap(0, size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fds[i], 0);

        g_assert(guest_mem != MAP_FAILED);
        guest_mem += (memory.regions[i].mmap_offset / sizeof(*guest_mem));

        for (j = 0; j < 256; j++) {
            uint32_t a = readl(memory.regions[i].guest_phys_addr + j*4);
            uint32_t b = guest_mem[j];

            g_assert_cmpint(a, ==, b);
        }

        munmap(guest_mem, memory.regions[i].memory_size);
    }

    g_assert_cmpint(1, ==, 1);
    g_mutex_unlock(&data_mutex);
}

static void *thread_function(void *data)
{
    GMainLoop *loop;
    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);
    return NULL;
}

static int chr_can_read(void *opaque)
{
    return VHOST_USER_HDR_SIZE;
}

static void chr_read(void *opaque, const uint8_t *buf, int size)
{
    CharDriverState *chr = opaque;
    VhostUserMsg msg;
    uint8_t *p = (uint8_t *) &msg;
    int fd;

    if (size != VHOST_USER_HDR_SIZE) {
        g_test_message("Wrong message size received %d\n", size);
        return;
    }

    g_mutex_lock(&data_mutex);
    memcpy(p, buf, VHOST_USER_HDR_SIZE);

    if (msg.size) {
        p += VHOST_USER_HDR_SIZE;
        qemu_chr_fe_read_all(chr, p, msg.size);
    }

    switch (msg.request) {
    case VHOST_USER_GET_FEATURES:
        /* send back features to qemu */
        msg.flags |= VHOST_USER_REPLY_MASK;
        msg.size = sizeof(m.u64);
        msg.u64 = 0x1ULL << VHOST_USER_F_PROTOCOL_FEATURES;
        p = (uint8_t *) &msg;
        qemu_chr_fe_write_all(chr, p, VHOST_USER_HDR_SIZE + msg.size);
        break;

    case VHOST_USER_SET_FEATURES:
	g_assert_cmpint(msg.u64 & (0x1ULL << VHOST_USER_F_PROTOCOL_FEATURES),
			!=, 0ULL);
        break;

    case VHOST_USER_GET_PROTOCOL_FEATURES:
        /* send back features to qemu */
        msg.flags |= VHOST_USER_REPLY_MASK;
        msg.size = sizeof(m.u64);
        msg.u64 = 0;
        p = (uint8_t *) &msg;
        qemu_chr_fe_write_all(chr, p, VHOST_USER_HDR_SIZE + msg.size);
        break;

    case VHOST_USER_GET_VRING_BASE:
        /* send back vring base to qemu */
        msg.flags |= VHOST_USER_REPLY_MASK;
        msg.size = sizeof(m.state);
        msg.state.num = 0;
        p = (uint8_t *) &msg;
        qemu_chr_fe_write_all(chr, p, VHOST_USER_HDR_SIZE + msg.size);
        break;

    case VHOST_USER_SET_MEM_TABLE:
        /* received the mem table */
        memcpy(&memory, &msg.memory, sizeof(msg.memory));
        fds_num = qemu_chr_fe_get_msgfds(chr, fds, sizeof(fds) / sizeof(int));

        /* signal the test that it can continue */
        g_cond_signal(&data_cond);
        break;

    case VHOST_USER_SET_VRING_KICK:
    case VHOST_USER_SET_VRING_CALL:
        /* consume the fd */
        qemu_chr_fe_get_msgfds(chr, &fd, 1);
        /*
         * This is a non-blocking eventfd.
         * The receive function forces it to be blocking,
         * so revert it back to non-blocking.
         */
        qemu_set_nonblock(fd);
        break;
    default:
        break;
    }
    g_mutex_unlock(&data_mutex);
}

static const char *init_hugepagefs(const char *path)
{
    struct statfs fs;
    int ret;

    if (access(path, R_OK | W_OK | X_OK)) {
        g_test_message("access on path (%s): %s\n", path, strerror(errno));
        return NULL;
    }

    do {
        ret = statfs(path, &fs);
    } while (ret != 0 && errno == EINTR);

    if (ret != 0) {
        g_test_message("statfs on path (%s): %s\n", path, strerror(errno));
        return NULL;
    }

    if (fs.f_type != HUGETLBFS_MAGIC) {
        g_test_message("Warning: path not on HugeTLBFS: %s\n", path);
        return NULL;
    }

    return path;
}

int main(int argc, char **argv)
{
    QTestState *s = NULL;
    CharDriverState *chr = NULL;
    const char *hugefs;
    char *socket_path = 0;
    char *qemu_cmd = 0;
    char *chr_path = 0;
    int ret;
    char template[] = "/tmp/vhost-test-XXXXXX";
    const char *tmpfs;
    const char *root;

    g_test_init(&argc, &argv, NULL);

    module_call_init(MODULE_INIT_QOM);

    tmpfs = mkdtemp(template);
    if (!tmpfs) {
          g_test_message("mkdtemp on path (%s): %s\n", template, strerror(errno));
    }
    g_assert(tmpfs);

    hugefs = getenv("QTEST_HUGETLBFS_PATH");
    if (hugefs) {
        root = init_hugepagefs(hugefs);
        g_assert(root);
    } else {
        root = tmpfs;
    }

    socket_path = g_strdup_printf("%s/vhost.sock", tmpfs);

    /* create char dev and add read handlers */
    qemu_add_opts(&qemu_chardev_opts);
    chr_path = g_strdup_printf("unix:%s,server,nowait", socket_path);
    chr = qemu_chr_new("chr0", chr_path, NULL);
    g_free(chr_path);
    qemu_chr_add_handlers(chr, chr_can_read, chr_read, NULL, chr);

    /* run the main loop thread so the chardev may operate */
    g_mutex_init(&data_mutex);
    g_cond_init(&data_cond);
    g_thread_new(NULL, thread_function, NULL);

    qemu_cmd = g_strdup_printf(QEMU_CMD, root, socket_path);
    s = qtest_start(qemu_cmd);
    g_free(qemu_cmd);

    qtest_add_func("/vhost-user/read-guest-mem", read_guest_mem);

    ret = g_test_run();

    if (s) {
        qtest_quit(s);
    }

    /* cleanup */
    unlink(socket_path);
    g_free(socket_path);

    ret = rmdir(tmpfs);
    if (ret != 0) {
        g_test_message("unable to rmdir: path (%s): %s\n",
                       tmpfs, strerror(errno));
    }
    g_assert_cmpint(ret, ==, 0);

    return ret;
}
