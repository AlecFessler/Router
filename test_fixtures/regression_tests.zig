//! Cross-cutting security regression tests.
//!
//! This file is its own test root (see `build.zig`). Audit branches add one
//! failing test per confirmed bug here. A regression test must encode the
//! *expected* (safe) router behavior, so it fails while the bug is present and
//! passes once the bug is fixed. Production code is intentionally not fixed by
//! the audit agents.
//!
//! Prefer a protocol-specific test file when the bug is local to one protocol
//! module. Use this file for bugs that span the Ethernet -> IPv4 -> transport
//! handler chain, tables, or end-to-end forwarding decisions.

const std = @import("std");
const Router = @import("router");

test {
    _ = Router;
}
