/*
 * Copyright 2018, 2020, 2023 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define __KERNEL__
#include <linux/stat.h>

#include "arraylist.h"
#include "assign5.h"
#include "hashmap.h"

arraylist_define(inodes, fuse_ino_t);

typedef struct
{
    fuse_ino_t inode;
    fuse_ino_t parent;
    struct stat* st;
    char* name;
    char* data;
    arraylist_inodes_t* children;
} fs_node;
fs_node dummy;

hashmap_define(fs, fuse_ino_t, fs_node*);

static hashmap_fs_t* fs;
static int inode_count;
static const char* features = "Features: \n"
                              "1. Core functions\n"
                              "2. Directory listing\n"
                              "3. Directory create and remove\n"
                              "4. File create and unlink\n"
                              "5. File modification"
                              "6. Permission manipulation\n";

static fuse_ino_t inode_hash(fuse_ino_t key)
{
    // MurmurHash3 64-bit Finalizer Mix Function
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccd;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53;
    key ^= key >> 33;
    return key;
}

static int next_inode()
{
    return ++inode_count;
}

static struct stat* stat_new_directory(mode_t mode, ino_t inode)
{
    struct stat* st = malloc(sizeof(struct stat));
    st->st_mode = S_IFDIR | mode;
    st->st_nlink = 1;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_size = 4096;
    st->st_blocks = st->st_size / 512;
    st->st_atime = time(NULL);
    st->st_mtime = time(NULL);
    st->st_ctime = time(NULL);
    st->st_ino = inode;
    return st;
}

static struct stat* stat_new_file(mode_t mode, size_t size, ino_t inode)
{
    struct stat* st = malloc(sizeof(struct stat));
    st->st_mode = S_IFREG | mode;
    st->st_nlink = 1;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_size = size;
    st->st_blocks = size / 512;
    st->st_atime = time(NULL);
    st->st_mtime = time(NULL);
    st->st_ctime = time(NULL);
    st->st_ino = inode;
    return st;
}

static fs_node* node_new(char* name, struct stat* st, fuse_ino_t parent, fuse_ino_t inode, char* data, arraylist_inodes_t* children)
{
    fs_node* node = malloc(sizeof(fs_node));
    node->name = name;
    node->st = st;
    node->parent = parent;
    node->inode = inode;
    node->data = data;
    node->children = children;
    return node;
}

static void stat_free(struct stat* st)
{
    free(st);
}

static void node_free(fs_node* node)
{
    free(node);
}

static struct fuse_entry_param myfs_dirent(fs_node* node)
{
    struct fuse_entry_param e = {
        .ino = node->inode,
        .generation = 1,
        .attr = *node->st,
        .attr_timeout = 1.0,
        .entry_timeout = 1.0,
    };
    return e;
}

static void myfs_init()
{
    fs = hashmap_fs_new(inode_hash);
    dummy.parent = 202191382;

    // inode=1 is a special case: it's the root directory
    // The system goes directly to inode=1 without lookups
    hashmap_fs_put(
        fs,
        1,
        node_new(
            strdup("/"),
            stat_new_directory(0755, 1),
            1, // parent
            1, // inode
            NULL,
            arraylist_inodes_new()));

    hashmap_fs_put(
        fs,
        2,
        node_new(
            strdup("assignment"),
            stat_new_directory(0777, 2),
            1, // parent
            2, // inode
            NULL,
            arraylist_inodes_new()));

    hashmap_fs_put(
        fs,
        3,
        node_new(
            strdup("username"),
            stat_new_file(0777, 6, 3),
            2, // parent
            3, // inode
            strdup("zguan"),
            NULL));

    hashmap_fs_put(
        fs,
        4,
        node_new(
            strdup("features"),
            stat_new_file(
                0777,
                strlen(features) + 1,
                4),
            2, // parent
            4, // inode
            strdup(features),
            NULL));

    arraylist_inodes_add(
        hashmap_fs_get_or_default(fs, 1, &dummy)->children, 2);
    arraylist_inodes_add(
        hashmap_fs_get_or_default(fs, 2, &dummy)->children, 3);
    arraylist_inodes_add(
        hashmap_fs_get_or_default(fs, 2, &dummy)->children, 4);

    inode_count = 4;
}

static int myfs_is_dummy(fs_node* node)
{
    return node->parent == 202191382;
}

static void myfs_destroy()
{
    for (int i = 0; i < fs->capacity; ++i) {
        if (!fs->buckets[i]) {
            continue;
        }

        for (llof(mapnode_fs_t)* n = fs->buckets[i]; n; n = n->next) {
            if (!n->data.value) {
                continue;
            }

            if (n->data.value->st) {
                stat_free(n->data.value->st);
            }

            if (n->data.value->children) {
                arraylist_inodes_free(n->data.value->children);
            }

            if (n->data.value->name) {
                free(n->data.value->name); // dealloc: node name
            }

            if (n->data.value->data) {
                free(n->data.value->data);
            }
            node_free(n->data.value);
        }
    }
    hashmap_fs_free(fs);
}

static struct stat* myfs_getattr(fuse_ino_t ino)
{
    fs_node* node = hashmap_fs_get_or_default(fs, ino, &dummy);
    if (myfs_is_dummy(node)) {
        return NULL;
    }
    return node->st;
}

static fs_node* myfs_lookup(fuse_ino_t parent, const char* name)
{
    // Locate parent
    if (!hashmap_fs_contains_key(fs, parent)) {
        return &dummy;
    }
    fs_node* parent_node = hashmap_fs_get_or_default(fs, parent, &dummy);

    // Locate child
    for (int i = 0; i < parent_node->children->size; ++i) {
        fuse_ino_t child = parent_node->children->data[i];
        fs_node* child_node = hashmap_fs_get_or_default(fs, child, &dummy);
        if (myfs_is_dummy(child_node)) {
            continue;
        }
        if (!strcmp(child_node->name, name)) {
            return child_node;
        }
    }
    return &dummy;
}

static fs_node* myfs_mk(fuse_ino_t parent, const char* name, struct stat* st, arraylist_inodes_t* children)
{
    // Locate parent
    fs_node* parent_node = hashmap_fs_get_or_default(fs, parent, &dummy);
    if (myfs_is_dummy(parent_node)) {
        return &dummy;
    }

    // Create child
    fs_node* child_node = node_new(
        strdup(name), // alloc: node name
        st,
        parent,
        st->st_ino,
        NULL,
        children);

    // Add child to parent
    arraylist_inodes_add(parent_node->children, child_node->st->st_ino);

    // Add child to fs
    hashmap_fs_put(fs, child_node->st->st_ino, child_node);

    return child_node;
}

static fs_node* myfs_mkdir(fuse_ino_t parent, const char* name, mode_t mode)
{
    return myfs_mk(parent, name, stat_new_directory(mode, next_inode()), arraylist_inodes_new());
}

static fs_node* myfs_mknod(fuse_ino_t parent, const char* name, mode_t mode, dev_t rdev)
{
    return myfs_mk(parent, name, stat_new_file(mode, 0, next_inode()), NULL);
}

static struct fuse_file_info* myfs_open(fuse_ino_t ino, struct fuse_file_info* fi)
{
    fs_node* node = hashmap_fs_get_or_default(fs, ino, &dummy);
    if (myfs_is_dummy(node)) {
        return NULL;
    }
    fi->fh = ino;
    return fi;
}

static void myfs_create_noreply(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode, struct fuse_file_info* fi)
{
    fs_node* node = myfs_lookup(parent, name);
    if (myfs_is_dummy(node)) {
        // Create if not exists
        node = myfs_mknod(parent, name, mode, 0);
        if (myfs_is_dummy(node)) {
            fuse_reply_err(req, ENOENT);
            return;
        }
    }
    struct fuse_file_info* ffi = myfs_open(node->st->st_ino, fi);
    struct fuse_entry_param fep = myfs_dirent(node);

    if (!ffi) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (fuse_reply_create(req, &fep, ffi)) {
        fprintf(stderr, "fuse_reply_create failed\n");
    }
}

static void myfs_readdir_noreply(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* fi)
{
    fs_node* node = hashmap_fs_get_or_default(fs, ino, &dummy);
    fs_node* parent = hashmap_fs_get_or_default(fs, node->parent, &dummy);

    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (!S_ISDIR(node->st->st_mode)) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    if (off >= node->children->size) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    off_t written = 0;
    int next = 0;
    char* buffer = (char*)malloc(size);
    struct stat* self = myfs_getattr(ino);
    memset(buffer, 0, size);

    for (int i = 0; i < node->children->capacity + 2; ++i) {
        // .
        if (i == 0) {
            written += fuse_add_direntry(req, buffer + written, size - written, ".", self, ++next);
        }
        // ..
        else if (i == 1) {
            written += fuse_add_direntry(req, buffer + written, size - written, "..", parent->st, ++next);
        }
        // Children
        else {
            fuse_ino_t child = node->children->data[i - 2];
            if (!hashmap_fs_contains_key(fs, child)) {
                continue;
            }

            fs_node* child_node = hashmap_fs_get_or_default(fs, child, &dummy);
            written += fuse_add_direntry(req, buffer + written, size - written, child_node->name, child_node->st, ++next);
        }

        /*
         * fuse_add_direntry
         *
         * Add a directory entry to the buffer Buffer needs to be large enough to hold the entry. If it's not, then the entry is not filled in but the size of the entry is still returned. The caller can check this by comparing the bufsize parameter with the returned entry size. If the entry size is larger than the buffer size, the operation failed.
         *
         */
        if (written >= size) {
            fuse_reply_buf(req, buffer, written);
            free(buffer);
            return;
        }
    }

    if (fuse_reply_buf(req, buffer, written)) {
        fprintf(stderr, "fuse_reply_buf failed\n");
    }

    free(buffer);
}

static void myfs_read_noreply(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* fi)
{
    /*
     * Read should send exactly the number of bytes requested except
     * on EOF or error, otherwise the rest of the data will be
     * substituted with zeroes.  An exception to this is when the file
     * has been opened in 'direct_io' mode, in which case the return
     * value of the read system call will reflect the return value of
     * this operation.
     *
     */

    fs_node* node = hashmap_fs_get_or_default(fs, ino, &dummy);
    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (S_ISDIR(node->st->st_mode)) {
        fuse_reply_err(req, EISDIR);
        return;
    }

    if (node->data == NULL) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    if (off >= node->st->st_size) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    if (off + size > node->st->st_size) {
        size = node->st->st_size - off;
    }

    char* buffer = (char*)malloc(size);
    memcpy(buffer, node->data + off, size);

    if (fuse_reply_buf(req, buffer, size)) {
        fprintf(stderr, "fuse_reply_buf failed\n");
    }
    free(buffer);
}

/**
 * @return 0 on success
 */
static int myfs_rmdir(fuse_ino_t parent, const char* name)
{
    fs_node* node = hashmap_fs_get_or_default(fs, parent, &dummy);
    if (myfs_is_dummy(node)) {
        return ENOENT;
    }

    if (!S_ISDIR(node->st->st_mode)) {
        return ENOTDIR;
    }

    for (int i = 0; i < node->children->size; ++i) {
        fuse_ino_t child = node->children->data[i];
        if (!hashmap_fs_contains_key(fs, child)) {
            continue;
        }

        fs_node* child_node = hashmap_fs_get_or_default(fs, child, &dummy);
        if (strcmp(child_node->name, name) == 0) {
            if (!S_ISDIR(child_node->st->st_mode)) {
                return ENOTDIR;
            }

            if (child_node->children->size > 0) {
                return ENOTEMPTY;
            }

            hashmap_fs_remove(fs, child);
            arraylist_inodes_remove(node->children, i);
            return 0;
        }
    }

    return ENOENT;
}

/**
 * @return 0 on success
 */
static void myfs_setattr_noreply(fuse_req_t req, fuse_ino_t ino, struct stat* attr, int to_set, struct fuse_file_info* fi)
{
    fs_node* node = hashmap_fs_get_or_default(fs, ino, &dummy);
    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (to_set & FUSE_SET_ATTR_MODE) {
        node->st->st_mode = attr->st_mode;
    }

    if (to_set & FUSE_SET_ATTR_UID) {
        node->st->st_uid = attr->st_uid;
    }

    if (to_set & FUSE_SET_ATTR_GID) {
        node->st->st_gid = attr->st_gid;
    }

    if (to_set & FUSE_SET_ATTR_SIZE) {
        if (node->data == NULL) {
            node->data = (char*)malloc(attr->st_size);
        } else {
            node->data = (char*)realloc(node->data, attr->st_size);
        }

        node->st->st_size = attr->st_size;
        node->st->st_blocks = attr->st_size / 512 + 1;
    }

    if (to_set & FUSE_SET_ATTR_ATIME) {
        node->st->st_atime = attr->st_atime;
    }

    if (to_set & FUSE_SET_ATTR_MTIME) {
        node->st->st_mtime = attr->st_mtime;
    }

    if (to_set & FUSE_SET_ATTR_ATIME_NOW) {
        node->st->st_atime = time(NULL);
    }

    if (to_set & FUSE_SET_ATTR_MTIME_NOW) {
        node->st->st_mtime = time(NULL);
    }

    fuse_reply_attr(req, node->st, 1.0);
}

static struct statvfs myfs_statfs(fuse_ino_t ino)
{
    struct statvfs stbuf = {
        .f_bsize = 512,
        .f_frsize = 512,
        .f_blocks = 1024 * 1024,
        .f_bfree = 1024 * 1024,
        .f_bavail = 1024 * 1024,
        .f_files = fs->size,
        .f_ffree = fs->capacity - fs->size,
        .f_favail = fs->capacity - fs->size,
        .f_fsid = 0,
        .f_flag = 0,
        .f_namemax = 255,
    };
    return stbuf;
}

static void myfs_unlink_noreply(fuse_req_t req, fuse_ino_t parent, const char* name)
{
    fs_node* node = hashmap_fs_get_or_default(fs, parent, &dummy);
    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (!S_ISDIR(node->st->st_mode)) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    for (int i = 0; i < node->children->size; ++i) {
        fuse_ino_t child = node->children->data[i];
        if (!hashmap_fs_contains_key(fs, child)) {
            continue;
        }

        fs_node* child_node = hashmap_fs_get_or_default(fs, child, &dummy);
        if (strcmp(child_node->name, name) == 0) {
            if (S_ISDIR(child_node->st->st_mode)) {
                fuse_reply_err(req, EISDIR);
                return;
            }

            hashmap_fs_remove(fs, child);
            arraylist_inodes_remove(node->children, i);
            fuse_reply_err(req, 0);
            return;
        }
    }

    fuse_reply_err(req, ENOENT);
}

static void myfs_write_noreply(fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size, off_t off, struct fuse_file_info* fi)
{
    fs_node* node = hashmap_fs_get_or_default(fs, ino, &dummy);

    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (S_ISDIR(node->st->st_mode)) {
        fuse_reply_err(req, EISDIR);
        return;
    }

    // Lazy allocation
    if (node->data == NULL) {
        node->data = (char*)malloc(off + size);
        node->st->st_size = off + size;
        node->st->st_blocks = node->st->st_size / 512 + 1;
    } else if (off + size > node->st->st_size) {
        node->data = (char*)realloc(node->data, off + size);
        node->st->st_size = off + size;
        node->st->st_blocks = node->st->st_size / 512 + 1;
    }

    memcpy(node->data + off, buf, size);
    node->st->st_mtime = time(NULL);

    fuse_reply_write(req, size);
}

//////////////////////////////////////////////////////////////////////////

static void
assign5_init(void* userdata, struct fuse_conn_info* conn)
{
    struct backing_file* backing = userdata;
    fprintf(stderr, "[init] %s '%s'\n", __func__, backing->bf_path);

    /*
     * This function should do some setup (e.g., open the backing file or
     * mmap(2) some memory) and prepare any metadata that you need.
     */
    myfs_init();
}

static void
assign5_destroy(void* userdata)
{
    struct backing_file* backing = userdata;
    fprintf(stderr, "[destroy] %s %d\n", __func__, backing->bf_fd);

    /*
     * Finalize any metadata, close any open files, etc.
     */
    myfs_destroy();
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L801 */
static void
assign5_create(fuse_req_t req, fuse_ino_t parent, const char* name,
    mode_t mode, struct fuse_file_info* fi)
{
    fprintf(stderr, "[create] %s parent=%zu name='%s' mode=%d\n", __func__, parent, name, mode);

    /*
     * Create and open a file.
     *
     * Respond by calling fuse_reply_err() if there's an error, or else
     * fuse_reply_create(), passing it information in a fuse_entry_param:
     *
     * https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L68
     *
     * This is the meaning of the "Valid replies" comment at
     * https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L791
     */
    myfs_create_noreply(req, parent, name, mode, fi);
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L256 */
static void
assign5_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fip)
{
    fprintf(stderr, "[getattr] %s ino=%zu\n", __func__, ino);
    struct stat* attr = myfs_getattr(ino);

    if (!attr) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (fuse_reply_attr(req, attr, 1)) {
        fprintf(stderr, "fuse_reply_attr failed\n");
    }
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L205 */
static void
assign5_lookup(fuse_req_t req, fuse_ino_t parent, const char* name)
{
    fprintf(stderr, "[lookup] %s parent=%zu name='%s'\n", __func__,
        parent, name);

    fs_node* node = myfs_lookup(parent, name);
    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct fuse_entry_param dirent = myfs_dirent(node);
    if (fuse_reply_entry(req, &dirent)) {
        fprintf(stderr, "fuse_reply_entry failed\n");
    }
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L332 */
static void
assign5_mkdir(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode)
{
    fprintf(stderr, "[mkdir] %s parent=%zu name='%s' mode=%d\n", __func__,
        parent, name, mode);

    fs_node* node = myfs_mkdir(parent, name, mode);
    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct fuse_entry_param dirent = myfs_dirent(node);
    if (fuse_reply_entry(req, &dirent)) {
        fprintf(stderr, "fuse_reply_entry failed\n");
    }
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L317 */
static void
assign5_mknod(fuse_req_t req, fuse_ino_t parent, const char* name,
    mode_t mode, dev_t rdev)
{
    fprintf(stderr, "[mknod] %s parent=%zu name='%s' mode=%d\n", __func__,
        parent, name, mode);

    fs_node* node = myfs_mknod(parent, name, mode, rdev);

    if (myfs_is_dummy(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct fuse_entry_param dirent = myfs_dirent(node);
    if (fuse_reply_entry(req, &dirent)) {
        fprintf(stderr, "fuse_reply_entry failed\n");
    }
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L444 */
static void
assign5_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    fprintf(stderr, "[open] %s ino=%zu\n", __func__, ino);
    struct fuse_file_info* ffi = myfs_open(ino, fi);
    if (ffi) {
        fuse_reply_open(req, ffi);
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L622 */
static void
assign5_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
    off_t off, struct fuse_file_info* fi)
{
    fprintf(stderr, "[readdir] %s ino=%zu size=%zu off=%zd\n", __func__,
        ino, size, off);
    myfs_readdir_noreply(req, ino, size, off, fi);
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L472 */
static void
assign5_read(fuse_req_t req, fuse_ino_t ino, size_t size,
    off_t off, struct fuse_file_info* fi)
{
    fprintf(stderr, "[read] %s ino=%zu size=%zu off=%zd\n", __func__,
        ino, size, off);
    myfs_read_noreply(req, ino, size, off, fi);
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L367 */
static void
assign5_rmdir(fuse_req_t req, fuse_ino_t parent, const char* name)
{
    fprintf(stderr, "[rmdir] %s parent=%zu name='%s'\n", __func__, parent, name);
    fuse_reply_err(req, myfs_rmdir(parent, name));
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L286 */
static void
assign5_setattr(fuse_req_t req, fuse_ino_t ino, struct stat* attr,
    int to_set, struct fuse_file_info* fi)
{
    fprintf(stderr, "[setattr] %s ino=%zu to_set=%d\n", __func__, ino, to_set);
    myfs_setattr_noreply(req, ino, attr, to_set, fi);
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L674 */
static void
assign5_statfs(fuse_req_t req, fuse_ino_t ino)
{
    fprintf(stderr, "[statfs] %s ino=%zu\n", __func__, ino);
    struct statvfs myfs_statfs_buf = myfs_statfs(ino);
    fuse_reply_statfs(req, &myfs_statfs_buf);
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L350 */
static void
assign5_unlink(fuse_req_t req, fuse_ino_t parent, const char* name)
{
    fprintf(stderr, "[unlink] %s parent=%zu name='%s'\n", __func__, parent, name);
    myfs_unlink_noreply(req, parent, name);
}

/* https://github.com/libfuse/libfuse/blob/fuse_2_9_bugfix/include/fuse_lowlevel.h#L498 */
static void
assign5_write(fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size, off_t off, struct fuse_file_info* fi)
{
    fprintf(stderr, "[write] %s ino=%zu size=%zu off=%zd\n", __func__,
        ino, size, off);
    myfs_write_noreply(req, ino, buf, size, off, fi);
}

static struct fuse_lowlevel_ops assign5_ops = {
    .init = assign5_init,
    .destroy = assign5_destroy,

    .create = assign5_create,
    .getattr = assign5_getattr,
    .lookup = assign5_lookup,
    .mkdir = assign5_mkdir,
    .mknod = assign5_mknod,
    .open = assign5_open,
    .read = assign5_read,
    .readdir = assign5_readdir,
    .rmdir = assign5_rmdir,
    .setattr = assign5_setattr,
    .statfs = assign5_statfs,
    .unlink = assign5_unlink,
    .write = assign5_write,
};

struct fuse_lowlevel_ops* assign5_fuse_ops()
{
    return &assign5_ops;
}
