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

#define FUSE_USE_VERSION 26
#include <fuse_lowlevel.h>

/**
 * Information about the file backing our filesystem
 */
struct backing_file {
/// Path to the file backing our filesystem
const char	*bf_path;

/// File descriptor of the backing file (if opened)
int		 bf_fd;
};

struct fuse_lowlevel_ops*	assign5_fuse_ops(void);
struct fuse_lowlevel_ops*	example_fuse_ops(void);
