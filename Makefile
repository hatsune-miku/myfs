#
# Copyright 2018, 2023 Jonathan Anderson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

CFLAGS=	-g -Wall `pkg-config --cflags fuse` \
	-I /usr/include/fuse \
	-D USE_EXAMPLE111111111 \
	-D_FILE_OFFSET_BITS=64 \
	-lfuse \
	-fsanitize=address -fno-omit-frame-pointer

LDFLAGS=`pkg-config --libs fuse` -fsanitize=address

OBJS=\
	assign5.o \
	example.o \
	main.o \

all: run-assign5
run-assign5: ${OBJS}
	${CC} ${OBJS} ${CFLAGS} ${LDFLAGS} -o run-assign5

# Express header dependencies: recompile these object files if header changes
example.o: assign5.h
fuse.o: assign5.h
main.o: assign5.h

clean:
	rm -f run-* *.o
