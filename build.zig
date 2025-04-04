const std = @import("std");

//const CFlags = &.{ "-fasm-blocks", "-masm=intel", "-fno-strict-aliasing" };

pub fn build(b: *std.Build) void {
    // Standard release options
    const optimize = b.standardOptimizeOption(.{
        // .preferred_optimize_mode = .ReleaseSmall,
    });

    const lib = b.addSharedLibrary(.{
        .name = "ZS",
        .root_source_file = b.path("src/main.zig"),
        .target = b.standardTargetOptions(.{
            .default_target = .{
                .cpu_arch = .x86_64,
                .os_tag = .windows,
                .abi = .gnu,
            },
        }),
        .optimize = optimize,
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
    });

    lib.linkage = .dynamic;
    lib.linkSystemLibrary("kernel32");
    lib.linkSystemLibrary("user32");
    lib.linkLibC();

    lib.use_llvm = true;

    b.installArtifact(lib);
}
