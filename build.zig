const std = @import("std");



pub fn build(b: *std.Build) void {
    // Standard release options
    const optimize = b.standardOptimizeOption(.{}); 
        // .preferred_optimize_mode = .ReleaseSmall,
    const target = b.standardTargetOptions(.{
      .default_target = .{
          .cpu_arch = .x86_64, 
          .os_tag = .windows, 
         // .abi = .windows,
      }
//      .resolveTargetQuery = .{ .cpu_arch = .aarch64, .os_tag = .windows };

    }); 
      
//    b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .windows });

    const lib = b.addLibrary(.{
        .name = "ZS",
        .linkage = .dynamic, 
        .root_module = b.createModule(. {

          .root_source_file = b.path("src/main.zig"),
          .target = target,
          .optimize = optimize,
        
       
        }),
        
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
    });

    lib.linkSystemLibrary("kernel32");
    lib.linkSystemLibrary("user32");
    lib.linkLibC();
    lib.use_llvm = true;

    b.installArtifact(lib);
}
