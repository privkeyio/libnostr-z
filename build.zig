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

    const noscrypt_c = b.addTranslateC(.{
        .root_source_file = b.path("src/noscrypt_c.h"),
        .target = target,
        .optimize = optimize,
    });
    noscrypt_c.addIncludePath(noscrypt.path("include"));
    const noscrypt_c_mod = noscrypt_c.createModule();

    const openssl_c = b.addTranslateC(.{
        .root_source_file = b.path("src/openssl_c.h"),
        .target = target,
        .optimize = optimize,
    });
    openssl_c.linkSystemLibrary("ssl", .{});
    openssl_c.linkSystemLibrary("crypto", .{});
    const openssl_c_mod = openssl_c.createModule();

    const nostr_mod = b.addModule("nostr", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "noscrypt_c", .module = noscrypt_c_mod },
            .{ .name = "openssl_c", .module = openssl_c_mod },
        },
    });

    nostr_mod.linkLibrary(noscrypt.artifact("noscrypt"));
    nostr_mod.linkLibrary(sz_lib);
    nostr_mod.addIncludePath(noscrypt.path("include"));
    nostr_mod.linkSystemLibrary("ssl", .{});
    nostr_mod.linkSystemLibrary("crypto", .{});

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "noscrypt_c", .module = noscrypt_c_mod },
                .{ .name = "openssl_c", .module = openssl_c_mod },
            },
        }),
    });

    // Recent glibc/binutils emit `.sframe` sections into the C runtime objects
    // (crt1.o, libc_nonshared.a) that Zig's self-hosted ELF linker cannot yet
    // relocate (R_X86_64_PC64), breaking `zig build test` on bleeding-edge
    // Linux distros. Routing through LLVM + LLD handles SFrame. See issue #114.
    if (b.option(bool, "lld", "Link with LLVM/LLD instead of Zig's self-hosted linker") orelse false) {
        tests.use_llvm = true;
        tests.use_lld = true;
    }
    tests.root_module.linkLibrary(noscrypt.artifact("noscrypt"));
    tests.root_module.linkLibrary(sz_lib);
    tests.root_module.addIncludePath(noscrypt.path("include"));
    tests.root_module.linkSystemLibrary("ssl", .{});
    tests.root_module.linkSystemLibrary("crypto", .{});

    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run tests").dependOn(&run_tests.step);
}
