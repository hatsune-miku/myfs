/**
 * @file  example.c
 * @brief This is a very simple example of a "filesystem" that uses hard-coded
 *        inodes and stat values to expose a read-only filesystem with no
 *        support for permissions, timestamps, etc.
 *
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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assign5.h"

// Some hard-coded inode numbers:
#define ROOT_DIR 1
#define ASSIGN_DIR 2
#define USERNAME_FILE 3
#define FILE_COUNT 3

// Hard-coded stat(2) information for each directory and file:
struct stat *file_stats;

// Hard-coded content of the "assignment/username" file:
static const char UsernameContent[] = "p15jra\n";

static void
example_init(void *userdata, struct fuse_conn_info *conn)
{
    struct backing_file *backing = userdata;
    fprintf(stderr, "*** %s '%s'\n", __func__, backing->bf_path);

    /*
     * This trivial example doesn't actually use the data stored in
     * the structure pointed at by `userdata`.
     *
     * It just statically creates all files and directories in an array.
     */

    file_stats = calloc(FILE_COUNT + 1, sizeof(*file_stats));

    static const int AllRead = S_IRUSR | S_IRGRP | S_IROTH;
    static const int AllExec = S_IXUSR | S_IXGRP | S_IXOTH;

    file_stats[ROOT_DIR].st_ino = ROOT_DIR;
    file_stats[ROOT_DIR].st_mode = S_IFDIR | AllRead | AllExec;
    file_stats[ROOT_DIR].st_nlink = 1;

    file_stats[ASSIGN_DIR].st_ino = ASSIGN_DIR;
    file_stats[ASSIGN_DIR].st_mode = S_IFDIR | AllRead | AllExec;
    file_stats[ASSIGN_DIR].st_nlink = 1;

    file_stats[USERNAME_FILE].st_ino = USERNAME_FILE;
    file_stats[USERNAME_FILE].st_mode = S_IFREG | AllRead;
    file_stats[USERNAME_FILE].st_size = sizeof(UsernameContent);
    file_stats[USERNAME_FILE].st_nlink = 1;
}

static void
example_destroy(void *userdata)
{
    struct backing_file *backing = userdata;
    fprintf(stderr, "*** %s %d\n", __func__, backing->bf_fd);

    free(file_stats);
    file_stats = NULL;
}

static void
example_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fip)
{
    fprintf(stderr, "*** %s ino=%zu\n", __func__, ino);

    if (ino > FILE_COUNT)
    {
        fuse_reply_err(req, ENOENT);
        return;
    }

    int result = fuse_reply_attr(req, file_stats + ino, 1);
    if (result != 0)
    {
        fprintf(stderr, "Failed to send attr reply\n");
    }
}

static void
example_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    fprintf(stderr, "*** %s parent=%zu name='%s'\n", __func__,
            parent, name);

    struct fuse_entry_param dirent;

    if (parent == ROOT_DIR && strcmp(name, "assignment") == 0)
    {
        // Looking for 'assignment' in the root directory
        dirent.ino = ASSIGN_DIR;
        dirent.attr = file_stats[ASSIGN_DIR];
    }
    else if (parent == ASSIGN_DIR && strcmp(name, "username") == 0)
    {
        // Looking for 'username' in the 'assignment' directory
        dirent.ino = USERNAME_FILE;
        dirent.attr = file_stats[USERNAME_FILE];
    }
    else
    {
        // Let all other names fail
        fuse_reply_err(req, ENOENT);
        return;
    }

    // I'm not re-using inodes, so I don't need to worry about real
    // generation numbers... always use the same one.
    dirent.generation = 1;

    // Assume that these values are always valid for 1s:
    dirent.attr_timeout = 1;
    dirent.entry_timeout = 1;

    int result = fuse_reply_entry(req, &dirent);
    if (result != 0)
    {
        fprintf(stderr, "Failed to send dirent reply\n");
    }
}

static void
example_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                off_t off, struct fuse_file_info *fi)
{
    fprintf(stderr, "*** %s ino=%zu size=%zu off=%zd\n", __func__,
            ino, size, off);

    // In our trivial example, all directories happen to have three
    // entries: ".", ".." and either "assignment" or "username".
    if (off > 2)
    {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    struct stat *self = file_stats + ino;
    if (!S_ISDIR(self->st_mode))
    {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    // In this trivial filesystem, the parent directory is always the root
    struct stat *parent = file_stats + ROOT_DIR;

    char buffer[size];
    off_t bytes = 0;
    int next = 0;

    if (off < 1)
    {
        bytes += fuse_add_direntry(req, buffer + bytes,
                                   sizeof(buffer) - bytes,
                                   ".", self, ++next);
    }

    if (off < 2)
    {
        bytes += fuse_add_direntry(req, buffer + bytes,
                                   sizeof(buffer) - bytes,
                                   "..", parent, ++next);
    }

    switch (ino)
    {
    case ROOT_DIR:
        bytes += fuse_add_direntry(req, buffer + bytes,
                                   sizeof(buffer) - bytes,
                                   "assignment",
                                   file_stats + ASSIGN_DIR,
                                   ++next);
        break;

    case ASSIGN_DIR:
        bytes += fuse_add_direntry(req, buffer + bytes,
                                   sizeof(buffer) - bytes,
                                   "username",
                                   file_stats + USERNAME_FILE,
                                   ++next);
        break;
    }

    int result = fuse_reply_buf(req, buffer, bytes);
    if (result != 0)
    {
        fprintf(stderr, "Failed to send readdir reply\n");
    }
}

static void
example_read(fuse_req_t req, fuse_ino_t ino, size_t size,
             off_t off, struct fuse_file_info *fi)
{
    fprintf(stderr, "*** %s ino=%zu size=%zu off=%zd\n", __func__,
            ino, size, off);

    const char *response_data = NULL;
    size_t response_len;
    int err = 0;

    switch (ino)
    {
    case ROOT_DIR:
    case ASSIGN_DIR:
        err = EISDIR;
        break;

    case USERNAME_FILE:
        if (off >= sizeof(UsernameContent))
        {
            response_len = 0;
            break;
        }

        response_data = UsernameContent + off;
        response_len = sizeof(UsernameContent) - off;
        if (response_len > size)
        {
            response_len = size;
        }
        break;

    default:
        err = EBADF;
    }

    if (err != 0)
    {
        fuse_reply_err(req, err);
        return;
    }

    assert(response_data != NULL);
    int result = fuse_reply_buf(req, response_data, response_len);
    if (result != 0)
    {
        fprintf(stderr, "Failed to send read reply\n");
    }
}

static struct fuse_lowlevel_ops example_ops = {
    .init = example_init,
    .destroy = example_destroy,

    .getattr = example_getattr,
    .lookup = example_lookup,
    .read = example_read,
    .readdir = example_readdir,
};

struct fuse_lowlevel_ops *
example_fuse_ops()
{
    return &example_ops;
}
