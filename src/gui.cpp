#include "gui.h"
#include "vault.h"
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <sstream>

// ---------------------------------------------------------------------------
// Resource IDs (defined inline — no .rc needed for these)
// ---------------------------------------------------------------------------
#define IDC_LIST_ENTRIES   1001
#define IDC_BTN_ADD        1002
#define IDC_BTN_EDIT       1003
#define IDC_BTN_DELETE     1004
#define IDC_BTN_SHOW       1005
#define IDC_BTN_COPY_PW    1006
#define IDC_BTN_CHANGE_MPW 1007
#define IDC_STATIC_STATUS  1008

// Login dialog
#define IDC_EDIT_MASTER_PW 2001
#define IDC_BTN_LOGIN      2002
#define IDC_BTN_SETUP      2003
#define IDC_STATIC_ERR     2004
#define IDC_STATIC_TITLE   2005

// Entry dialog
#define IDC_EDIT_TITLE     3001
#define IDC_EDIT_USERNAME  3002
#define IDC_EDIT_PASSWORD  3003
#define IDC_EDIT_URL       3004
#define IDC_EDIT_NOTES     3005
#define IDC_CHK_SHOW_PW    3006
#define IDC_BTN_GENERATE   3007

// Change master password dialog
#define IDC_EDIT_OLD_PW    4001
#define IDC_EDIT_NEW_PW    4002
#define IDC_EDIT_CONF_PW   4003

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static Vault*   g_vault     = nullptr;
static HWND     g_hwndMain  = nullptr;
static HWND     g_hwndList  = nullptr;
static bool     g_pw_visible[10000] = {}; // per-entry show state (capped)
static HFONT    g_hFont     = nullptr;
static HFONT    g_hFontBold = nullptr;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}
static std::string to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}
static std::string get_edit_text(HWND hEdit) {
    int len = GetWindowTextLengthW(hEdit);
    if (len <= 0) return {};
    std::wstring w(len + 1, 0);
    GetWindowTextW(hEdit, w.data(), len + 1);
    w.resize(len);
    return to_utf8(w);
}
static void set_edit_text(HWND hEdit, const std::string& s) {
    SetWindowTextW(hEdit, to_wide(s).c_str());
}
static void copy_to_clipboard(HWND hwnd, const std::string& text) {
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    auto w = to_wide(text);
    size_t bytes = (w.size() + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hg) {
        void* p = GlobalLock(hg);
        memcpy(p, w.c_str(), bytes);
        GlobalUnlock(hg);
        SetClipboardData(CF_UNICODETEXT, hg);
    }
    CloseClipboard();
}

static std::string generate_password(int len = 16) {
    const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}";
    int clen = (int)strlen(charset);
    // Use CryptGenRandom via Crypto::random_bytes indirectly
    HCRYPTPROV prov = 0;
    CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    std::string pw(len, ' ');
    for (int i = 0; i < len; i++) {
        BYTE b;
        CryptGenRandom(prov, 1, &b);
        pw[i] = charset[b % clen];
    }
    CryptReleaseContext(prov, 0);
    return pw;
}

static HFONT create_font(int size, bool bold) {
    return CreateFontW(size, 0, 0, 0,
        bold ? FW_BOLD : FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
}

// ---------------------------------------------------------------------------
// Refresh the list view
// ---------------------------------------------------------------------------
static void refresh_list() {
    if (!g_hwndList) return;
    SendMessageW(g_hwndList, LVM_DELETEALLITEMS, 0, 0);
    const auto& entries = g_vault->entries();
    for (int i = 0; i < (int)entries.size(); i++) {
        const auto& e = entries[i];
        LVITEMW lvi = {};
        lvi.mask    = LVIF_TEXT;
        lvi.iItem   = i;
        lvi.iSubItem = 0;
        auto wtitle = to_wide(e.title.empty() ? "(no title)" : e.title);
        lvi.pszText = wtitle.data();
        ListView_InsertItem(g_hwndList, &lvi);

        auto wuser = to_wide(e.username);
        ListView_SetItemText(g_hwndList, i, 1, wuser.data());

        std::wstring wpw;
        if (i < 10000 && g_pw_visible[i])
            wpw = to_wide(e.password);
        else
            wpw = std::wstring(e.password.size(), L'*');
        ListView_SetItemText(g_hwndList, i, 2, wpw.data());

        auto wurl = to_wide(e.url);
        ListView_SetItemText(g_hwndList, i, 3, wurl.data());
    }
}

// ---------------------------------------------------------------------------
// Entry Add/Edit dialog
// ---------------------------------------------------------------------------
struct EntryDlgParam {
    PasswordEntry entry;
    bool          is_edit;
    bool          ok;
};

static INT_PTR CALLBACK EntryDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static EntryDlgParam* p = nullptr;
    switch (msg) {
    case WM_INITDIALOG: {
        p = reinterpret_cast<EntryDlgParam*>(lParam);
        SetWindowTextW(hDlg, p->is_edit ? L"Edit Entry" : L"Add Entry");
        if (p->is_edit) {
            set_edit_text(GetDlgItem(hDlg, IDC_EDIT_TITLE),    p->entry.title);
            set_edit_text(GetDlgItem(hDlg, IDC_EDIT_USERNAME),  p->entry.username);
            set_edit_text(GetDlgItem(hDlg, IDC_EDIT_PASSWORD),  p->entry.password);
            set_edit_text(GetDlgItem(hDlg, IDC_EDIT_URL),       p->entry.url);
            set_edit_text(GetDlgItem(hDlg, IDC_EDIT_NOTES),     p->entry.notes);
        }
        // Password hidden by default
        SendMessageW(GetDlgItem(hDlg, IDC_EDIT_PASSWORD), EM_SETPASSWORDCHAR, L'*', 0);
        return TRUE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_CHK_SHOW_PW) {
            bool checked = (IsDlgButtonChecked(hDlg, IDC_CHK_SHOW_PW) == BST_CHECKED);
            SendMessageW(GetDlgItem(hDlg, IDC_EDIT_PASSWORD),
                EM_SETPASSWORDCHAR, checked ? 0 : L'*', 0);
            InvalidateRect(GetDlgItem(hDlg, IDC_EDIT_PASSWORD), nullptr, TRUE);
        } else if (id == IDC_BTN_GENERATE) {
            auto pw = generate_password(16);
            set_edit_text(GetDlgItem(hDlg, IDC_EDIT_PASSWORD), pw);
            // Show after generate
            CheckDlgButton(hDlg, IDC_CHK_SHOW_PW, BST_CHECKED);
            SendMessageW(GetDlgItem(hDlg, IDC_EDIT_PASSWORD), EM_SETPASSWORDCHAR, 0, 0);
            InvalidateRect(GetDlgItem(hDlg, IDC_EDIT_PASSWORD), nullptr, TRUE);
        } else if (id == IDOK) {
            p->entry.title    = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_TITLE));
            p->entry.username = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_USERNAME));
            p->entry.password = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_PASSWORD));
            p->entry.url      = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_URL));
            p->entry.notes    = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_NOTES));
            if (p->entry.title.empty()) {
                MessageBoxW(hDlg, L"Title cannot be empty.", L"Validation", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            p->ok = true;
            EndDialog(hDlg, IDOK);
        } else if (id == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
        }
        return TRUE;
    }
    }
    return FALSE;
}

// Entry dialog template built in memory
static DLGTEMPLATE* build_entry_dlg_template() {
    // We'll use DialogBoxIndirectParam with a manually built template
    // Layout: Title, Username, Password (with show checkbox + generate btn), URL, Notes, OK, Cancel
    struct DlgData {
        DLGTEMPLATE tmpl;
        WORD menu, cls, title[10];
    };
    static uint8_t buf[4096] = {};
    memset(buf, 0, sizeof(buf));

    auto align4 = [](uint8_t* p) -> uint8_t* {
        uintptr_t v = (uintptr_t)p;
        return p + ((4 - (v & 3)) & 3);
    };

    DLGTEMPLATE* dt = reinterpret_cast<DLGTEMPLATE*>(buf);
    dt->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER | DS_SETFONT;
    dt->dwExtendedStyle = 0;
    dt->cdit = 0; // we'll count manually
    dt->x = 0; dt->y = 0; dt->cx = 260; dt->cy = 230;

    uint8_t* p = buf + sizeof(DLGTEMPLATE);
    // menu = 0
    *(WORD*)p = 0; p += 2;
    // class = 0
    *(WORD*)p = 0; p += 2;
    // title
    wcscpy((wchar_t*)p, L"Entry"); p += (wcslen(L"Entry") + 1) * 2;
    // font size + name
    *(WORD*)p = 9; p += 2;
    wcscpy((wchar_t*)p, L"Segoe UI"); p += (wcslen(L"Segoe UI") + 1) * 2;

    // Helper lambda to add a control
    int ctrl_count = 0;
    auto add_ctrl = [&](short x, short y, short cx, short cy,
                        DWORD style, DWORD exstyle, WORD cls_atom,
                        const wchar_t* cls_str, const wchar_t* text, WORD id) {
        p = align4(p);
        DLGITEMTEMPLATE* di = reinterpret_cast<DLGITEMTEMPLATE*>(p);
        di->style = style | WS_CHILD | WS_VISIBLE;
        di->dwExtendedStyle = exstyle;
        di->x = x; di->y = y; di->cx = cx; di->cy = cy;
        di->id = id;
        p += sizeof(DLGITEMTEMPLATE);
        if (cls_atom) { *(WORD*)p = 0xFFFF; p += 2; *(WORD*)p = cls_atom; p += 2; }
        else { wcscpy((wchar_t*)p, cls_str); p += (wcslen(cls_str)+1)*2; }
        if (text) { wcscpy((wchar_t*)p, text); p += (wcslen(text)+1)*2; }
        else { *(WORD*)p = 0; p += 2; }
        *(WORD*)p = 0; p += 2; // no creation data
        ctrl_count++;
    };

    // Labels + Edits
    // Title
    add_ctrl(7,8,50,10,SS_RIGHT,0,0x0082,nullptr,L"Title:",     0xFFFF);
    add_ctrl(60,7,185,14,WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,0,0x0081,nullptr,nullptr,IDC_EDIT_TITLE);
    // Username
    add_ctrl(7,26,50,10,SS_RIGHT,0,0x0082,nullptr,L"Username:",  0xFFFF);
    add_ctrl(60,25,185,14,WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,0,0x0081,nullptr,nullptr,IDC_EDIT_USERNAME);
    // Password
    add_ctrl(7,44,50,10,SS_RIGHT,0,0x0082,nullptr,L"Password:",  0xFFFF);
    add_ctrl(60,43,130,14,WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD,0,0x0081,nullptr,nullptr,IDC_EDIT_PASSWORD);
    add_ctrl(195,43,50,14,WS_TABSTOP|BS_AUTOCHECKBOX,0,0x0080,nullptr,L"Show",IDC_CHK_SHOW_PW);
    // Generate button
    add_ctrl(60,60,70,13,WS_TABSTOP|BS_PUSHBUTTON,0,0x0080,nullptr,L"Generate",IDC_BTN_GENERATE);
    // URL
    add_ctrl(7,77,50,10,SS_RIGHT,0,0x0082,nullptr,L"URL:",       0xFFFF);
    add_ctrl(60,76,185,14,WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,0,0x0081,nullptr,nullptr,IDC_EDIT_URL);
    // Notes
    add_ctrl(7,94,50,10,SS_RIGHT,0,0x0082,nullptr,L"Notes:",     0xFFFF);
    add_ctrl(60,93,185,60,WS_BORDER|WS_TABSTOP|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL,0,0x0081,nullptr,nullptr,IDC_EDIT_NOTES);
    // OK / Cancel
    add_ctrl(120,157+10,60,14,WS_TABSTOP|BS_DEFPUSHBUTTON,0,0x0080,nullptr,L"Save",IDOK);
    add_ctrl(185,157+10,60,14,WS_TABSTOP|BS_PUSHBUTTON,0,0x0080,nullptr,L"Cancel",IDCANCEL);

    dt->cdit = (WORD)ctrl_count;
    return dt;
}

// ---------------------------------------------------------------------------
// Login dialog
// ---------------------------------------------------------------------------
struct LoginDlgParam {
    Vault*       vault;
    std::string  vault_path;
    bool         ok;
};

static INT_PTR CALLBACK LoginDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static LoginDlgParam* p = nullptr;
    switch (msg) {
    case WM_INITDIALOG: {
        p = reinterpret_cast<LoginDlgParam*>(lParam);
        SendMessageW(GetDlgItem(hDlg, IDC_EDIT_MASTER_PW), EM_SETPASSWORDCHAR, L'*', 0);
        if (p->vault->is_new()) {
            SetWindowTextW(hDlg, L"Set Up Vault");
            SetDlgItemTextW(hDlg, IDC_STATIC_TITLE, L"Create a master password to protect your vault.");
            ShowWindow(GetDlgItem(hDlg, IDC_BTN_LOGIN), SW_HIDE);
            ShowWindow(GetDlgItem(hDlg, IDC_BTN_SETUP), SW_SHOW);
        } else {
            SetWindowTextW(hDlg, L"Unlock Vault");
            SetDlgItemTextW(hDlg, IDC_STATIC_TITLE, L"Enter your master password to unlock the vault.");
            ShowWindow(GetDlgItem(hDlg, IDC_BTN_LOGIN), SW_SHOW);
            ShowWindow(GetDlgItem(hDlg, IDC_BTN_SETUP), SW_HIDE);
        }
        SetFocus(GetDlgItem(hDlg, IDC_EDIT_MASTER_PW));
        return FALSE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_BTN_LOGIN || id == IDC_BTN_SETUP ||
            (id == IDC_EDIT_MASTER_PW && HIWORD(wParam) == EN_CHANGE && 0)) {
            // handle Enter in edit box via IDOK
        }
        if (id == IDOK || id == IDC_BTN_LOGIN || id == IDC_BTN_SETUP) {
            auto pw = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_MASTER_PW));
            if (pw.empty()) {
                SetDlgItemTextW(hDlg, IDC_STATIC_ERR, L"Password cannot be empty.");
                return TRUE;
            }
            if (p->vault->is_new()) {
                if (pw.size() < 8) {
                    SetDlgItemTextW(hDlg, IDC_STATIC_ERR, L"Password must be at least 8 characters.");
                    return TRUE;
                }
                SetDlgItemTextW(hDlg, IDC_STATIC_ERR, L"Creating vault, please wait...");
                UpdateWindow(hDlg);
                if (!p->vault->setup(p->vault_path, pw)) {
                    SetDlgItemTextW(hDlg, IDC_STATIC_ERR, L"Failed to create vault.");
                    return TRUE;
                }
            } else {
                SetDlgItemTextW(hDlg, IDC_STATIC_ERR, L"Unlocking, please wait...");
                UpdateWindow(hDlg);
                if (!p->vault->unlock(pw)) {
                    SetDlgItemTextW(hDlg, IDC_STATIC_ERR, L"Incorrect password. Try again.");
                    SetDlgItemTextW(hDlg, IDC_EDIT_MASTER_PW, L"");
                    return TRUE;
                }
            }
            p->ok = true;
            EndDialog(hDlg, IDOK);
        } else if (id == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
        }
        return TRUE;
    }
    }
    return FALSE;
}

static DLGTEMPLATE* build_login_dlg_template() {
    static uint8_t buf[4096] = {};
    memset(buf, 0, sizeof(buf));

    auto align4 = [](uint8_t* p) -> uint8_t* {
        return p + ((4 - ((uintptr_t)p & 3)) & 3);
    };

    DLGTEMPLATE* dt = reinterpret_cast<DLGTEMPLATE*>(buf);
    dt->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER | DS_SETFONT;
    dt->cdit = 0;
    dt->x = 0; dt->y = 0; dt->cx = 230; dt->cy = 110;

    uint8_t* p = buf + sizeof(DLGTEMPLATE);
    *(WORD*)p = 0; p += 2;
    *(WORD*)p = 0; p += 2;
    wcscpy((wchar_t*)p, L"Vault"); p += (wcslen(L"Vault") + 1) * 2;
    *(WORD*)p = 9; p += 2;
    wcscpy((wchar_t*)p, L"Segoe UI"); p += (wcslen(L"Segoe UI") + 1) * 2;

    int ctrl_count = 0;
    auto add_ctrl = [&](short x, short y, short cx, short cy,
                        DWORD style, WORD cls_atom, const wchar_t* text, WORD id) {
        p = align4(p);
        DLGITEMTEMPLATE* di = reinterpret_cast<DLGITEMTEMPLATE*>(p);
        di->style = style | WS_CHILD | WS_VISIBLE;
        di->dwExtendedStyle = 0;
        di->x = x; di->y = y; di->cx = cx; di->cy = cy; di->id = id;
        p += sizeof(DLGITEMTEMPLATE);
        *(WORD*)p = 0xFFFF; p += 2; *(WORD*)p = cls_atom; p += 2;
        if (text) { wcscpy((wchar_t*)p, text); p += (wcslen(text)+1)*2; }
        else { *(WORD*)p = 0; p += 2; }
        *(WORD*)p = 0; p += 2;
        ctrl_count++;
    };

    add_ctrl(7,7,216,18, SS_LEFT, 0x0082, L"", IDC_STATIC_TITLE);
    add_ctrl(7,30,216,14, WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD, 0x0081, nullptr, IDC_EDIT_MASTER_PW);
    add_ctrl(7,50,216,12, SS_LEFT, 0x0082, L"", IDC_STATIC_ERR);
    add_ctrl(70,68,75,14, WS_TABSTOP|BS_DEFPUSHBUTTON, 0x0080, L"Unlock", IDC_BTN_LOGIN);
    add_ctrl(70,68,75,14, WS_TABSTOP|BS_DEFPUSHBUTTON, 0x0080, L"Create Vault", IDC_BTN_SETUP);
    add_ctrl(150,68,75,14, WS_TABSTOP|BS_PUSHBUTTON,   0x0080, L"Exit", IDCANCEL);

    dt->cdit = (WORD)ctrl_count;
    return dt;
}

// ---------------------------------------------------------------------------
// Change master password dialog
// ---------------------------------------------------------------------------
static INT_PTR CALLBACK ChangeMPWDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        SendMessageW(GetDlgItem(hDlg, IDC_EDIT_OLD_PW), EM_SETPASSWORDCHAR, L'*', 0);
        SendMessageW(GetDlgItem(hDlg, IDC_EDIT_NEW_PW), EM_SETPASSWORDCHAR, L'*', 0);
        SendMessageW(GetDlgItem(hDlg, IDC_EDIT_CONF_PW), EM_SETPASSWORDCHAR, L'*', 0);
        return TRUE;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDOK) {
            auto old_pw  = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_OLD_PW));
            auto new_pw  = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_NEW_PW));
            auto conf_pw = get_edit_text(GetDlgItem(hDlg, IDC_EDIT_CONF_PW));
            if (new_pw != conf_pw) {
                MessageBoxW(hDlg, L"New passwords do not match.", L"Error", MB_OK | MB_ICONERROR);
                return TRUE;
            }
            if (new_pw.size() < 8) {
                MessageBoxW(hDlg, L"New password must be at least 8 characters.", L"Error", MB_OK | MB_ICONERROR);
                return TRUE;
            }
            if (!g_vault->change_master_password(old_pw, new_pw)) {
                MessageBoxW(hDlg, L"Current password is incorrect.", L"Error", MB_OK | MB_ICONERROR);
                return TRUE;
            }
            MessageBoxW(hDlg, L"Master password changed successfully.", L"Success", MB_OK | MB_ICONINFORMATION);
            EndDialog(hDlg, IDOK);
        } else if (id == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
        }
        return TRUE;
    }
    }
    return FALSE;
}

static DLGTEMPLATE* build_change_mpw_template() {
    static uint8_t buf[4096] = {};
    memset(buf, 0, sizeof(buf));
    auto align4 = [](uint8_t* p)->uint8_t*{ return p+((4-((uintptr_t)p&3))&3); };

    DLGTEMPLATE* dt = reinterpret_cast<DLGTEMPLATE*>(buf);
    dt->style = WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_MODALFRAME|DS_CENTER|DS_SETFONT;
    dt->x=0;dt->y=0;dt->cx=200;dt->cy=110;

    uint8_t* p = buf + sizeof(DLGTEMPLATE);
    *(WORD*)p=0;p+=2; *(WORD*)p=0;p+=2;
    wcscpy((wchar_t*)p,L"Change Master Password");p+=(wcslen(L"Change Master Password")+1)*2;
    *(WORD*)p=9;p+=2; wcscpy((wchar_t*)p,L"Segoe UI");p+=(wcslen(L"Segoe UI")+1)*2;

    int n=0;
    auto ac=[&](short x,short y,short cx,short cy,DWORD style,WORD cls,const wchar_t* txt,WORD id){
        p=align4(p);
        auto di=reinterpret_cast<DLGITEMTEMPLATE*>(p);
        di->style=style|WS_CHILD|WS_VISIBLE;di->dwExtendedStyle=0;
        di->x=x;di->y=y;di->cx=cx;di->cy=cy;di->id=id;
        p+=sizeof(DLGITEMTEMPLATE);
        *(WORD*)p=0xFFFF;p+=2;*(WORD*)p=cls;p+=2;
        if(txt){wcscpy((wchar_t*)p,txt);p+=(wcslen(txt)+1)*2;}else{*(WORD*)p=0;p+=2;}
        *(WORD*)p=0;p+=2;n++;
    };
    ac(7,7,100,10,SS_LEFT,0x0082,L"Current password:",0xFFFF);
    ac(110,6,80,14,WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD,0x0081,nullptr,IDC_EDIT_OLD_PW);
    ac(7,24,100,10,SS_LEFT,0x0082,L"New password:",0xFFFF);
    ac(110,23,80,14,WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD,0x0081,nullptr,IDC_EDIT_NEW_PW);
    ac(7,41,100,10,SS_LEFT,0x0082,L"Confirm new:",0xFFFF);
    ac(110,40,80,14,WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD,0x0081,nullptr,IDC_EDIT_CONF_PW);
    ac(55,60,80,14,WS_TABSTOP|BS_DEFPUSHBUTTON,0x0080,L"Change",IDOK);
    ac(140,60,55,14,WS_TABSTOP|BS_PUSHBUTTON,0x0080,L"Cancel",IDCANCEL);
    dt->cdit=(WORD)n;
    return dt;
}

// ---------------------------------------------------------------------------
// Main window procedure
// ---------------------------------------------------------------------------
static void do_add(HWND hwnd) {
    EntryDlgParam param{}; param.is_edit = false; param.ok = false;
    DialogBoxIndirectParamW(GetModuleHandleW(nullptr),
        build_entry_dlg_template(), hwnd, EntryDlgProc, (LPARAM)&param);
    if (param.ok) {
        g_vault->add_entry(param.entry);
        g_vault->save();
        refresh_list();
    }
}

static void do_edit(HWND hwnd) {
    int sel = ListView_GetNextItem(g_hwndList, -1, LVNI_SELECTED);
    if (sel < 0) { MessageBoxW(hwnd, L"Select an entry to edit.", L"Info", MB_OK); return; }
    EntryDlgParam param{};
    param.entry   = g_vault->entries()[sel];
    param.is_edit = true; param.ok = false;
    DialogBoxIndirectParamW(GetModuleHandleW(nullptr),
        build_entry_dlg_template(), hwnd, EntryDlgProc, (LPARAM)&param);
    if (param.ok) {
        g_vault->update_entry(sel, param.entry);
        g_vault->save();
        refresh_list();
    }
}

static void do_delete(HWND hwnd) {
    int sel = ListView_GetNextItem(g_hwndList, -1, LVNI_SELECTED);
    if (sel < 0) { MessageBoxW(hwnd, L"Select an entry to delete.", L"Info", MB_OK); return; }
    auto& e = g_vault->entries()[sel];
    std::wstring msg = L"Delete entry \"" + to_wide(e.title) + L"\"?";
    if (MessageBoxW(hwnd, msg.c_str(), L"Confirm Delete", MB_YESNO | MB_ICONWARNING) == IDYES) {
        if (sel < 10000) g_pw_visible[sel] = false;
        g_vault->delete_entry(sel);
        g_vault->save();
        refresh_list();
    }
}

static void do_toggle_show(HWND hwnd) {
    int sel = ListView_GetNextItem(g_hwndList, -1, LVNI_SELECTED);
    if (sel < 0) { MessageBoxW(hwnd, L"Select an entry.", L"Info", MB_OK); return; }
    if (sel < 10000) g_pw_visible[sel] = !g_pw_visible[sel];
    refresh_list();
    // Update button text
    HWND btn = GetDlgItem(hwnd, IDC_BTN_SHOW);
    SetWindowTextW(btn, (sel < 10000 && g_pw_visible[sel]) ? L"Hide Password" : L"Show Password");
}

static void do_copy_pw(HWND hwnd) {
    int sel = ListView_GetNextItem(g_hwndList, -1, LVNI_SELECTED);
    if (sel < 0) { MessageBoxW(hwnd, L"Select an entry.", L"Info", MB_OK); return; }
    copy_to_clipboard(hwnd, g_vault->entries()[sel].password);
    SetDlgItemTextW(hwnd, IDC_STATIC_STATUS, L"Password copied to clipboard.");
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Toolbar buttons
        auto mkbtn = [&](const wchar_t* text, int id, int x, int y, int cx, int cy) {
            HWND b = CreateWindowExW(0, L"BUTTON", text,
                WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,
                x, y, cx, cy, hwnd, (HMENU)(UINT_PTR)id, GetModuleHandleW(nullptr), nullptr);
            if (g_hFont) SendMessageW(b, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        };
        mkbtn(L"Add",             IDC_BTN_ADD,        5,   5, 80, 26);
        mkbtn(L"Edit",            IDC_BTN_EDIT,       90,  5, 80, 26);
        mkbtn(L"Delete",          IDC_BTN_DELETE,     175, 5, 80, 26);
        mkbtn(L"Show Password",   IDC_BTN_SHOW,       260, 5, 105,26);
        mkbtn(L"Copy Password",   IDC_BTN_COPY_PW,    370, 5, 105,26);
        mkbtn(L"Change Master PW",IDC_BTN_CHANGE_MPW, 480, 5, 140,26);

        // Status bar label
        HWND hs = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD|WS_VISIBLE|SS_LEFT,
            5, 35, 700, 14, hwnd, (HMENU)IDC_STATIC_STATUS,
            GetModuleHandleW(nullptr), nullptr);
        if (g_hFont) SendMessageW(hs, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        // List view
        RECT rc; GetClientRect(hwnd, &rc);
        g_hwndList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS,
            0, 55, rc.right, rc.bottom - 55,
            hwnd, (HMENU)IDC_LIST_ENTRIES, GetModuleHandleW(nullptr), nullptr);
        ListView_SetExtendedListViewStyle(g_hwndList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);

        auto addcol = [](HWND lv, int i, const wchar_t* hdr, int w) {
            LVCOLUMNW c = {}; c.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
            c.iSubItem = i; c.cx = w; c.pszText = (LPWSTR)hdr;
            ListView_InsertColumn(lv, i, &c);
        };
        addcol(g_hwndList, 0, L"Title",    180);
        addcol(g_hwndList, 1, L"Username", 160);
        addcol(g_hwndList, 2, L"Password", 140);
        addcol(g_hwndList, 3, L"URL",      200);

        if (g_hFont) SendMessageW(g_hwndList, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        refresh_list();
        return 0;
    }
    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        if (g_hwndList) SetWindowPos(g_hwndList, nullptr, 0, 55, w, h - 55, SWP_NOZORDER);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        SetDlgItemTextW(hwnd, IDC_STATIC_STATUS, L"");
        switch (id) {
        case IDC_BTN_ADD:        do_add(hwnd);        break;
        case IDC_BTN_EDIT:       do_edit(hwnd);       break;
        case IDC_BTN_DELETE:     do_delete(hwnd);     break;
        case IDC_BTN_SHOW:       do_toggle_show(hwnd); break;
        case IDC_BTN_COPY_PW:    do_copy_pw(hwnd);    break;
        case IDC_BTN_CHANGE_MPW:
            DialogBoxIndirectParamW(GetModuleHandleW(nullptr),
                build_change_mpw_template(), hwnd, ChangeMPWDlgProc, 0);
            break;
        }
        return 0;
    }
    case WM_NOTIFY: {
        NMHDR* nm = reinterpret_cast<NMHDR*>(lParam);
        if (nm->idFrom == IDC_LIST_ENTRIES && nm->code == NM_DBLCLK)
            do_edit(hwnd);
        // Reset show button text on selection change
        if (nm->idFrom == IDC_LIST_ENTRIES && nm->code == LVN_ITEMCHANGED) {
            int sel = ListView_GetNextItem(g_hwndList, -1, LVNI_SELECTED);
            HWND btn = GetDlgItem(hwnd, IDC_BTN_SHOW);
            if (sel >= 0 && sel < 10000 && g_pw_visible[sel])
                SetWindowTextW(btn, L"Hide Password");
            else
                SetWindowTextW(btn, L"Show Password");
        }
        return 0;
    }
    case WM_DESTROY:
        g_vault->lock();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// RunApp
// ---------------------------------------------------------------------------
int RunApp(HINSTANCE hInstance, int nCmdShow, Vault& vault, const std::string& vault_path) {
    g_vault = &vault;
    InitCommonControls();

    g_hFont     = create_font(-13, false);
    g_hFontBold = create_font(-13, true);

    // Show login dialog
    LoginDlgParam ldp{ &vault, vault_path, false };
    INT_PTR lr = DialogBoxIndirectParamW(hInstance,
        build_login_dlg_template(), nullptr, LoginDlgProc, (LPARAM)&ldp);
    if (lr != IDOK || !ldp.ok) return 0;

    // Register main window class
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"PasswordManagerMain";
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_hwndMain = CreateWindowExW(0, L"PasswordManagerMain",
        L"Password Manager & Encrypter",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 780, 520,
        nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hwndMain, nCmdShow);
    UpdateWindow(g_hwndMain);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_hFont)     DeleteObject(g_hFont);
    if (g_hFontBold) DeleteObject(g_hFontBold);
    return (int)msg.wParam;
}
