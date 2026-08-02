# frozen_string_literal: true

require "mkmf"

native_root = File.expand_path("../../native/autotype", __dir__)
native_src = File.join(native_root, "src")
native_include = File.join(native_root, "include")

$CFLAGS << " -O3 -std=c11 -Wall -Wextra -DNDEBUG"
$CFLAGS << " -I#{native_include}"

$VPATH << native_src
$srcs = %w[type.c solver.c autotype.c]

create_makefile("autotype")
