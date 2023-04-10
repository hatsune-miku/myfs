/*
 * Copyright 2018, 2023 Jonathan Anderson
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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "assign5.h"

static void
print_usage()
{
    fprintf(stderr,
            "Usage:  fuse [options] <mountpoint> <fs_filename>\n"
            "\n"
            "Options:\n"
            "  -f    foreground (don't daemonize)\n"
            "  -d    debug output (implies -f)\n");
}

int main(int argc, char *argv[])
{
    //
    // Parse command-line arguments
    //
    struct fuse_args args = {
        .argc = argc - 1,
        .argv = argv,
        .allocated = 0,
    };

    if (argc < 2)
    {
        print_usage();
        return 1;
    }

    struct backing_file backing = {
        .bf_path = argv[argc - 1],
        .bf_fd = -1,
    };

    char *mountpoint;
    int foreground, multi;

    int ret = fuse_parse_cmdline(&args, &mountpoint, &multi, &foreground);
    if (ret != 0 || !mountpoint || backing.bf_path == mountpoint)
    {
        print_usage();
        goto done;
    }

    // Set `ret` to -1 in case any of the following operations fail (and
    // boot us straight to the end of main())
    ret = -1;

    // Create the FUSE mountpoint
    struct fuse_chan *channel = fuse_mount(mountpoint, &args);
    if (channel == NULL)
    {
        goto err_with_args;
    }

//
// Construct a "low level" FUSE session with student-provided operations
//
#ifdef USE_EXAMPLE
    struct fuse_lowlevel_ops *ops = example_fuse_ops();
#else
    struct fuse_lowlevel_ops *ops = assign5_fuse_ops();
#endif
    if (ops == NULL)
    {
        goto err_with_channel;
    }

    struct fuse_session *se =
        fuse_lowlevel_new(&args, ops, sizeof(*ops), &backing);
    if (se == NULL)
    {
        goto err_with_channel;
    }

    fuse_session_add_chan(se, channel);

    // Handle HUP, TERM and INT for clean shutdown
    if (fuse_set_signal_handlers(se) != 0)
    {
        goto err_with_session;
    }

    // Go into the background (unless `-f` and/or `-d` are set)
    if (fuse_daemonize(foreground) != 0)
    {
        goto err_with_session;
    }

    // Block until process terminated or filesystem unmounted
    if (multi)
    {
        ret = fuse_session_loop_mt(se);
    }
    else
    {
        ret = fuse_session_loop(se);
    }

    // Reset signal handlers to defaults
    fuse_remove_signal_handlers(se);

//
// Cleanup in reverse order
//
err_with_session:
    fuse_session_remove_chan(channel);
    fuse_session_destroy(se);

err_with_channel:
    fuse_unmount(mountpoint, channel);

err_with_args:
    free(mountpoint);
    fuse_opt_free_args(&args);

done:
    return ret;
}
