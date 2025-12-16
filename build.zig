const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const noscrypt = b.dependency("noscrypt", .{
        .target = target,
        .optimize = optimize,
    });

    const stringzilla = b.dependency("stringzilla", .{
        .target = target,
        .optimize = optimize,
    });

    const sz_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sz_mod.addCSourceFile(.{
        .file = b.path("src/sz_wrapper.c"),
        .flags = &.{ "-std=c99", "-O3" },
    });
    sz_mod.addIncludePath(stringzilla.path("include"));

    const sz_lib = b.addLibrary(.{
        .name = "sz_wrapper",
        .root_module = sz_mod,
        .linkage = .static,
    });

    const nostr_mod = b.addModule("nostr", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    nostr_mod.linkLibrary(noscrypt.artifact("noscrypt"));
    nostr_mod.linkLibrary(sz_lib);
    nostr_mod.addIncludePath(noscrypt.path("include"));

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.linkLibrary(noscrypt.artifact("noscrypt"));
    tests.linkLibrary(sz_lib);
    tests.root_module.addIncludePath(noscrypt.path("include"));
    tests.linkLibC();

    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run tests").dependOn(&run_tests.step);
}
