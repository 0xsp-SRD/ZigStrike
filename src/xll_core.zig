//Author : @Zux0x3a
//Date : 2025-03-02
//Version : 1.0
//Description : This is the core of the xll project.

const std = @import("std");
const win32 = std.os.windows;

const ID_STATIC_TEXT = 1001;
const ID_CHECKBOX = 1002;
const ID_OK = 1003;
const ID_CANCEL = 1004;
const WM_COMMAND = 0x0111;
const WM_CREATE = 0x0001;
const WM_DESTROY = 0x0002;
pub var g_bChecked: bool = false;
const BST_CHECKED = 1;
const BST_UNCHECKED = 0;
const WS_OVERLAPPEDWINDOW = 0x00000000;
const WS_VISIBLE = 0x10000000;
const CW_USEDEFAULT = 0x80000000;
const WS_CHILD = 0x40000000;
const BS_CHECKBOX = 0x00000002;
const BS_DEFPUSHBUTTON = 0x00000001;
const WS_OVERLAPPED = 0x00000000;
const WS_CAPTION = 0x00C00000;
const WS_SYSMENU = 0x00080000;
const WS_THICKFRAME = 0x00040000;
const WS_MINIMIZEBOX = 0x00020000;
const WS_MAXIMIZEBOX = 0x00010000;
pub const MB_OK = 0x00000000;
const WNDPROC = *const fn (hWnd: win32.HWND, uMsg: win32.UINT, wParam: win32.WPARAM, lParam: win32.LPARAM) callconv(.c) win32.LRESULT;

const WNDCLASSEXW = extern struct {
    cbSize: win32.UINT,
    style: win32.UINT,
    lpfnWndProc: WNDPROC,
    cbClsExtra: win32.INT,
    cbWndExtra: win32.INT,
    hInstance: win32.HINSTANCE,
    hIcon: ?win32.HICON,
    hCursor: ?win32.HCURSOR,
    hbrBackground: ?win32.HBRUSH,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: [*:0]const u16,
    hIconSm: ?win32.HICON,
};
const MSG = extern struct {
    hwnd: win32.HWND,
    message: win32.UINT,
    wParam: win32.WPARAM,
    lParam: win32.LPARAM,
    time: win32.DWORD,
    pt: win32.POINT,
};
// list of APIs calls.
extern fn CreateWindowExW(dwExStyle: win32.DWORD, lpClassName: [*:0]const u16, lpWindowName: [*:0]const u16, dwStyle: win32.DWORD, x: win32.INT, y: win32.INT, nWidth: win32.INT, nHeight: win32.INT, hWndParent: ?win32.HWND, hMenu: ?win32.HMENU, hInstance: ?win32.HINSTANCE, lpParam: ?win32.LPVOID) callconv(.c) win32.HWND;
extern fn PostQuitMessage(nExitCode: win32.INT) callconv(.c) win32.LRESULT;
extern fn DefWindowProcW(hWnd: win32.HWND, uMsg: win32.UINT, wParam: win32.WPARAM, lParam: win32.LPARAM) callconv(.c) win32.LRESULT;
extern fn IsDlgButtonChecked(hDlg: win32.HWND, nIDButton: win32.INT) callconv(.c) win32.INT;
extern fn DestroyWindow(hWnd: win32.HWND) callconv(.c) win32.LRESULT;
extern fn GetMessageW(lpMsg: *MSG, hWnd: ?win32.HWND, wMsgFilterMin: win32.UINT, wMsgFilterMax: win32.UINT) callconv(.c) win32.LRESULT;
extern fn TranslateMessage(lpMsg: *MSG) callconv(.c) win32.LRESULT;
extern fn DispatchMessageW(lpMsg: *MSG) callconv(.c) win32.LRESULT;
extern fn RegisterClassExW(lpWndClass: *const WNDCLASSEXW) callconv(.c) win32.ATOM;
extern fn GetModuleHandleW(lpModuleName: [*:0]const u16) callconv(.c) win32.HMODULE;

pub extern fn MessageBoxW(hWnd: ?win32.HWND, lpText: [*:0]const u16, lpCaption: [*:0]const u16, uType: win32.UINT) callconv(.c) win32.INT;

pub fn LOWORD(x: win32.WPARAM) win32.WORD {
    return @intCast(x & 0xFFFF);
}

pub fn HIWORD(x: win32.WPARAM) win32.WORD {
    return @intCast((x >> 16) & 0xFFFF);
}
fn WndProc(hWnd: win32.HWND, uMsg: win32.UINT, wParam: win32.WPARAM, lParam: win32.LPARAM) callconv(.c) win32.LRESULT {
    switch (uMsg) {
        WM_CREATE => {
            _ = CreateWindowExW(0, std.unicode.utf8ToUtf16LeStringLiteral("STATIC"), std.unicode.utf8ToUtf16LeStringLiteral("Do you want to proceed?"), WS_VISIBLE | WS_CHILD, 10, 10, 260, 20, hWnd, @ptrFromInt(ID_STATIC_TEXT), null, null);
            //   _ = CreateWindowExW(0, std.unicode.utf8ToUtf16LeStringLiteral("BUTTON"), std.unicode.utf8ToUtf16LeStringLiteral("Enable Feature"), WS_VISIBLE | WS_CHILD | BS_CHECKBOX, 10, 40, 260, 20, hWnd, @ptrFromInt(ID_CHECKBOX), null, null);
            _ = CreateWindowExW(0, std.unicode.utf8ToUtf16LeStringLiteral("BUTTON"), std.unicode.utf8ToUtf16LeStringLiteral("OK"), WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 50, 80, 80, 24, hWnd, @ptrFromInt(ID_OK), null, null);
            _ = CreateWindowExW(0, std.unicode.utf8ToUtf16LeStringLiteral("BUTTON"), std.unicode.utf8ToUtf16LeStringLiteral("Cancel"), WS_VISIBLE | WS_CHILD, 140, 80, 80, 24, hWnd, @ptrFromInt(ID_CANCEL), null, null);
            return 0;
        },
        WM_COMMAND => {
            const id = LOWORD(wParam);

            if (id == ID_CHECKBOX) {
                g_bChecked = (IsDlgButtonChecked(hWnd, ID_CHECKBOX) == BST_CHECKED);
                return 0;
            } else if (id == ID_OK) {
                g_bChecked = true;
                //     g_bChecked = (IsDlgButtonChecked(hWnd, ID_CHECKBOX) == BST_CHECKED);
                // _ = DestroyWindow(hWnd);
                if (g_bChecked) {
                    _ = MessageBoxW(null, std.unicode.utf8ToUtf16LeStringLiteral("Feature enabled"), std.unicode.utf8ToUtf16LeStringLiteral("Success"), MB_OK);
                } else {
                    _ = MessageBoxW(null, std.unicode.utf8ToUtf16LeStringLiteral("Feature disabled"), std.unicode.utf8ToUtf16LeStringLiteral("Success"), MB_OK);
                }
                _ = DestroyWindow(hWnd);
                //  return true;
            } else if (id == ID_CANCEL) {
                g_bChecked = false;
                _ = MessageBoxW(null, std.unicode.utf8ToUtf16LeStringLiteral("Feature cancelled"), std.unicode.utf8ToUtf16LeStringLiteral("Success"), MB_OK);

                _ = DestroyWindow(hWnd);
            }
            return 0;
        },
        WM_DESTROY => {
            _ = PostQuitMessage(0);
            return 0;
        },
        else => {
            return DefWindowProcW(hWnd, uMsg, wParam, lParam);
        },
    }
}

pub fn ShowCheckboxDialog() bool {
    //  const hInstance = GetModuleHandleW(@as([*:0]const u16, @ptrCast(&[_:0]u16{0})));
    const hInstance = @as(win32.HINSTANCE, @ptrCast(GetModuleHandleW(@as([*:0]const u16, @ptrCast(&[_:0]u16{0})))));

    const className = std.unicode.utf8ToUtf16LeStringLiteral("CheckboxDialogClass");

    // Register window class
    var wc: WNDCLASSEXW = .{
        .cbSize = @sizeOf(WNDCLASSEXW),
        .style = 0,
        .lpfnWndProc = WndProc,
        .cbClsExtra = 0,
        .cbWndExtra = 0,
        .hInstance = hInstance,
        .hIcon = null,
        .hCursor = null,
        .hbrBackground = null,
        .lpszMenuName = null,
        .lpszClassName = className,
        .hIconSm = null,
    };
    _ = RegisterClassExW(&wc);

    // Create the window
    const hDlg = CreateWindowExW(0, className, std.unicode.utf8ToUtf16LeStringLiteral("Checkbox Dialog"), WS_OVERLAPPEDWINDOW | WS_VISIBLE, @as(win32.INT, @bitCast(@as(win32.UINT, CW_USEDEFAULT))), @as(win32.INT, @bitCast(@as(win32.UINT, CW_USEDEFAULT))), 300, 150, null, null, hInstance, null);
    if (@as(?win32.HWND, hDlg) == null) return false;
    //std.debug.print("hDlg: {}\n", .{hDlg});
    // Message loop
    var msg: MSG = undefined;
    while (GetMessageW(&msg, null, 0, 0) > 0) {
        _ = TranslateMessage(&msg);
        _ = DispatchMessageW(&msg);
    }

    return g_bChecked;
}
