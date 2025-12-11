const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const noscrypt = b.dependency("noscrypt", .{
        .target = target,
        .optimize = optimize,
    });

    const nostr_mod = b.addModule("nostr", .{
        .root_source_file = b.path("src/nostr.zig"),
        .target = target,
        .optimize = optimize,
    });

    nostr_mod.linkLibrary(noscrypt.artifact("noscrypt"));
    nostr_mod.addIncludePath(noscrypt.path("include"));

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/nostr.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.linkLibrary(noscrypt.artifact("noscrypt"));
    tests.root_module.addIncludePath(noscrypt.path("include"));
    tests.linkLibC();

    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run tests").dependOn(&run_tests.step);
}
