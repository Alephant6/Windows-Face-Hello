// Drives the FaceHello Credential Provider DLL the way LogonUI would, without a sign-in screen.
//
// Usage: harness.exe <FaceHelloCP.dll> <user SID string> <user account name> <log file>
//
// Must run as LocalSystem next to a pipe server that is also LocalSystem (cp/tests/mock_service.py):
// the provider verifies the pipe server identity and reads the LSA secret L$FaceHello_<user>.
// The mock service answers every face check with "success" for the name in
// C:\Users\Public\mock-user.txt, which this harness rewrites per scenario.
#include <windows.h>
#include <credentialprovider.h>
#include <shlwapi.h>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <initguid.h>

DEFINE_GUID(CLSID_FaceHelloProviderForTest,
    0xe071a7ce, 0x5d7f, 0x4063, 0x9a, 0x10, 0xae, 0x39, 0xae, 0xc6, 0x4e, 0xe8);
DEFINE_GUID(GUID_ProviderLogoForTest,
    0x2d837775, 0xf6cd, 0x464e, 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93);
DEFINE_GUID(GUID_ProviderLabelForTest,
    0x286bbff3, 0xbad4, 0x438f, 0xb0, 0x07, 0x79, 0xb7, 0x26, 0x7c, 0x3d, 0x48);

namespace
{
FILE* g_log = nullptr;
int g_failures = 0;
int g_checks = 0;

void Logf(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("%s\n", buf);
    if (g_log)
    {
        fprintf(g_log, "%s\n", buf);
        fflush(g_log);
    }
}

void Check(bool ok, const char* what)
{
    ++g_checks;
    if (!ok)
    {
        ++g_failures;
    }
    Logf("%s  %s", ok ? "PASS" : "FAIL", what);
}

std::string Narrow(const std::wstring& w)
{
    if (w.empty())
    {
        return {};
    }
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
}

void WriteTextFile(const wchar_t* path, const char* text)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(h, text, static_cast<DWORD>(strlen(text)), &written, nullptr);
        CloseHandle(h);
    }
}

class RefCounted
{
public:
    RefCounted() : _ref(1) {}
    virtual ~RefCounted() {}
    ULONG AddRefImpl() { return static_cast<ULONG>(InterlockedIncrement(&_ref)); }
    ULONG ReleaseImpl()
    {
        const LONG r = InterlockedDecrement(&_ref);
        if (r == 0)
        {
            delete this;
        }
        return static_cast<ULONG>(r);
    }

private:
    LONG _ref;
};

class FakeUser : public ICredentialProviderUser, public RefCounted
{
public:
    explicit FakeUser(const std::wstring& sid) : _sid(sid) {}
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ICredentialProviderUser))
        {
            *ppv = static_cast<ICredentialProviderUser*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return AddRefImpl(); }
    IFACEMETHODIMP_(ULONG) Release() { return ReleaseImpl(); }
    IFACEMETHODIMP GetSid(LPWSTR* sid) { return SHStrDupW(_sid.c_str(), sid); }
    IFACEMETHODIMP GetProviderID(GUID* providerID)
    {
        *providerID = GUID_NULL;
        return S_OK;
    }
    IFACEMETHODIMP GetStringValue(REFPROPERTYKEY, LPWSTR* stringValue)
    {
        *stringValue = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetValue(REFPROPERTYKEY, PROPVARIANT*) { return E_NOTIMPL; }

private:
    std::wstring _sid;
};

class FakeUserArray : public ICredentialProviderUserArray, public RefCounted
{
public:
    explicit FakeUserArray(const std::wstring& sid) : _sid(sid) {}
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ICredentialProviderUserArray))
        {
            *ppv = static_cast<ICredentialProviderUserArray*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return AddRefImpl(); }
    IFACEMETHODIMP_(ULONG) Release() { return ReleaseImpl(); }
    IFACEMETHODIMP SetProviderFilter(REFGUID) { return S_OK; }
    IFACEMETHODIMP GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* options)
    {
        *options = CPAO_NONE;
        return S_OK;
    }
    IFACEMETHODIMP GetCount(DWORD* userCount)
    {
        *userCount = 1;
        return S_OK;
    }
    IFACEMETHODIMP GetAt(DWORD userIndex, ICredentialProviderUser** user)
    {
        if (userIndex != 0)
        {
            *user = nullptr;
            return E_INVALIDARG;
        }
        *user = new FakeUser(_sid);
        return S_OK;
    }

private:
    std::wstring _sid;
};

class ProviderEvents : public ICredentialProviderEvents, public RefCounted
{
public:
    ProviderEvents() : changed(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}
    ~ProviderEvents() { CloseHandle(changed); }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ICredentialProviderEvents))
        {
            *ppv = static_cast<ICredentialProviderEvents*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return AddRefImpl(); }
    IFACEMETHODIMP_(ULONG) Release() { return ReleaseImpl(); }
    IFACEMETHODIMP CredentialsChanged(UINT_PTR)
    {
        SetEvent(changed);
        return S_OK;
    }
    HANDLE changed;
};

class CredentialEvents : public ICredentialProviderCredentialEvents, public RefCounted
{
public:
    CredentialEvents() { InitializeCriticalSection(&_cs); }
    ~CredentialEvents() { DeleteCriticalSection(&_cs); }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ICredentialProviderCredentialEvents))
        {
            *ppv = static_cast<ICredentialProviderCredentialEvents*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return AddRefImpl(); }
    IFACEMETHODIMP_(ULONG) Release() { return ReleaseImpl(); }
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_STATE) { return S_OK; }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) { return S_OK; }
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*, DWORD, LPCWSTR psz)
    {
        EnterCriticalSection(&_cs);
        _lastString = psz ? psz : L"";
        LeaveCriticalSection(&_cs);
        return S_OK;
    }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, LPCWSTR) { return S_OK; }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, LPCWSTR) { return S_OK; }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP OnCreatingWindow(HWND* phwndOwner)
    {
        *phwndOwner = nullptr;
        return E_NOTIMPL;
    }
    std::wstring LastString()
    {
        EnterCriticalSection(&_cs);
        std::wstring s = _lastString;
        LeaveCriticalSection(&_cs);
        return s;
    }

private:
    CRITICAL_SECTION _cs;
    std::wstring _lastString;
};

typedef HRESULT(__stdcall* DllGetClassObjectFn)(REFCLSID, REFIID, void**);
DllGetClassObjectFn g_getClassObject = nullptr;

ICredentialProvider* NewProvider()
{
    IClassFactory* factory = nullptr;
    if (FAILED(g_getClassObject(CLSID_FaceHelloProviderForTest, IID_PPV_ARGS(&factory))) || !factory)
    {
        return nullptr;
    }
    ICredentialProvider* provider = nullptr;
    factory->CreateInstance(nullptr, IID_PPV_ARGS(&provider));
    factory->Release();
    return provider;
}

// One provider + its single bound credential, set up the way LogonUI would at a console sign-in.
struct Session
{
    ICredentialProvider* provider = nullptr;
    ICredentialProviderCredential* credential = nullptr;
    ProviderEvents* providerEvents = nullptr;
    CredentialEvents* credentialEvents = nullptr;
    DWORD count = 0;
    DWORD defaultIndex = 0;
    BOOL autoLogon = FALSE;

    bool Open(const std::wstring& sid, bool withUsers)
    {
        provider = NewProvider();
        if (!provider)
        {
            return false;
        }
        if (FAILED(provider->SetUsageScenario(CPUS_LOGON, 0)))
        {
            return false;
        }
        if (withUsers)
        {
            ICredentialProviderSetUserArray* setUsers = nullptr;
            if (FAILED(provider->QueryInterface(IID_PPV_ARGS(&setUsers))) || !setUsers)
            {
                return false;
            }
            FakeUserArray* users = new FakeUserArray(sid);
            const HRESULT hr = setUsers->SetUserArray(users);
            users->Release();
            setUsers->Release();
            if (FAILED(hr))
            {
                return false;
            }
        }
        providerEvents = new ProviderEvents();
        provider->Advise(providerEvents, 42);
        if (FAILED(provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)) || count == 0)
        {
            return false;
        }
        if (FAILED(provider->GetCredentialAt(0, &credential)) || !credential)
        {
            return false;
        }
        credentialEvents = new CredentialEvents();
        credential->Advise(credentialEvents);
        return true;
    }

    // What LogonUI does when the user presses the submit arrow.
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE Submit(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* out)
    {
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        PWSTR text = nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_NONE;
        ZeroMemory(out, sizeof(*out));
        credential->GetSerialization(&response, out, &text, &icon);
        CoTaskMemFree(text);
        return response;
    }

    bool WaitChanged(DWORD ms) { return WaitForSingleObject(providerEvents->changed, ms) == WAIT_OBJECT_0; }

    void Close()
    {
        if (credential)
        {
            credential->SetDeselected();
            credential->UnAdvise();
            credential->Release();
            credential = nullptr;
        }
        if (provider)
        {
            provider->UnAdvise();
            provider->Release();
            provider = nullptr;
        }
        if (credentialEvents)
        {
            credentialEvents->Release();
            credentialEvents = nullptr;
        }
        if (providerEvents)
        {
            providerEvents->Release();
            providerEvents = nullptr;
        }
    }
};

const wchar_t kMockUserFile[] = L"C:\\Users\\Public\\mock-user.txt";
const wchar_t kAutoStartFile[] = L"C:\\ProgramData\\FaceHello\\autostart.txt";
} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc < 5)
    {
        printf("usage: harness <dll> <sid> <user> <log>\n");
        return 2;
    }
    const std::wstring dllPath = argv[1];
    const std::wstring sid = argv[2];
    const std::wstring userName = argv[3];
    _wfopen_s(&g_log, argv[4], L"w");

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    HMODULE dll = LoadLibraryW(dllPath.c_str());
    Check(dll != nullptr, "DLL loads");
    if (!dll)
    {
        Logf("RESULT: FAIL (%d of %d checks failed)", g_failures, g_checks);
        return 1;
    }
    g_getClassObject = reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(dll, "DllGetClassObject"));
    Check(g_getClassObject != nullptr, "DllGetClassObject is exported");
    if (!g_getClassObject)
    {
        Logf("RESULT: FAIL (%d of %d checks failed)", g_failures, g_checks);
        return 1;
    }
    DeleteFileW(kAutoStartFile);
    const std::string userUtf8 = Narrow(userName);

    // ---- 1. shape of the bound credential ----
    Logf("--- scenario 1: credential bound to the user's tile");
    {
        WriteTextFile(kMockUserFile, userUtf8.c_str());
        Session s;
        const bool opened = s.Open(sid, true);
        Check(opened, "provider accepts CPUS_LOGON and a user array, and enumerates a credential");
        if (opened)
        {
            Check(s.count == 1, "one credential for one user");
            Check(s.defaultIndex == CREDENTIAL_PROVIDER_NO_DEFAULT, "bound credential does not claim to be the default");
            Check(s.autoLogon == FALSE, "no auto logon before any face check");

            ICredentialProviderCredential2* c2 = nullptr;
            const HRESULT hr2 = s.credential->QueryInterface(IID_PPV_ARGS(&c2));
            Check(SUCCEEDED(hr2) && c2 != nullptr, "bound credential exposes ICredentialProviderCredential2");
            if (c2)
            {
                PWSTR got = nullptr;
                const HRESULT hrSid = c2->GetUserSid(&got);
                Check(hrSid == S_OK && got && sid == got, "GetUserSid returns the user's SID");
                CoTaskMemFree(got);
                c2->Release();
            }

            DWORD fields = 0;
            s.provider->GetFieldDescriptorCount(&fields);
            Check(fields == 5, "five field descriptors");
            bool logo = false;
            bool label = false;
            for (DWORD i = 0; i < fields; ++i)
            {
                CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* d = nullptr;
                if (SUCCEEDED(s.provider->GetFieldDescriptorAt(i, &d)) && d)
                {
                    if (d->cpft == CPFT_TILE_IMAGE && d->guidFieldType == GUID_ProviderLogoForTest)
                    {
                        logo = true;
                    }
                    if (d->cpft == CPFT_SMALL_TEXT && d->guidFieldType == GUID_ProviderLabelForTest)
                    {
                        label = true;
                        PWSTR text = nullptr;
                        const HRESULT hrText = s.credential->GetStringValue(d->dwFieldID, &text);
                        Check(SUCCEEDED(hrText) && text && text[0] != L'\0', "provider label field has text");
                        CoTaskMemFree(text);
                        CREDENTIAL_PROVIDER_FIELD_STATE fs = CPFS_DISPLAY_IN_BOTH;
                        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE fis = CPFIS_NONE;
                        s.credential->GetFieldState(d->dwFieldID, &fs, &fis);
                        Check(fs == CPFS_HIDDEN, "provider label field is hidden on the tile");
                    }
                    if (d->cpft == CPFT_TILE_IMAGE)
                    {
                        HBITMAP bmp = nullptr;
                        const HRESULT hrBmp = s.credential->GetBitmapValue(d->dwFieldID, &bmp);
                        Check(SUCCEEDED(hrBmp) && bmp != nullptr, "tile image bitmap is returned");
                        if (bmp)
                        {
                            DeleteObject(bmp);
                        }
                    }
                    CoTaskMemFree(d->pszLabel);
                    CoTaskMemFree(d);
                }
            }
            Check(logo, "tile image is marked as the provider logo");
            Check(label, "a small-text field is marked as the provider label");
        }
        s.Close();
    }

    // ---- 2. recognized as the bound user: auto logon + serialization ----
    Logf("--- scenario 2: face recognized as this user");
    {
        WriteTextFile(kMockUserFile, userUtf8.c_str());
        Session s;
        if (s.Open(sid, true))
        {
            BOOL autoOnSelect = TRUE;
            s.credential->SetSelected(&autoOnSelect);
            Check(autoOnSelect == FALSE, "selecting the tile does not itself log on");
            Check(!s.WaitChanged(1500), "no face check starts on selection when autostart is off");
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION ser;
            Check(s.Submit(&ser) == CPGSR_NO_CREDENTIAL_NOT_FINISHED, "first submit starts the check and returns not-finished");
            const bool changed = s.WaitChanged(15000);
            Check(changed, "provider signals CredentialsChanged after recognition");
            if (!changed)
            {
                Logf("      last status: %s", Narrow(s.credentialEvents->LastString()).c_str());
            }
            DWORD count = 0;
            DWORD def = 0;
            BOOL autoLogon = FALSE;
            s.provider->GetCredentialCount(&count, &def, &autoLogon);
            Check(count == 1 && def == 0 && autoLogon == TRUE, "GetCredentialCount now asks for auto logon with this credential");
            const CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE resp = s.Submit(&ser);
            Check(resp == CPGSR_RETURN_CREDENTIAL_FINISHED, "second GetSerialization returns a finished credential");
            Check(ser.rgbSerialization != nullptr && ser.cbSerialization > 0, "serialization blob is not empty");
            Check(ser.clsidCredentialProvider == CLSID_FaceHelloProviderForTest, "serialization names this provider");
            if (resp != CPGSR_RETURN_CREDENTIAL_FINISHED)
            {
                Logf("      last status: %s", Narrow(s.credentialEvents->LastString()).c_str());
            }
            CoTaskMemFree(ser.rgbSerialization);
            s.provider->GetCredentialCount(&count, &def, &autoLogon);
            Check(autoLogon == FALSE, "auto logon request is cleared after the credential was taken");
        }
        else
        {
            Check(false, "scenario 2 could not open a session");
        }
        s.Close();
    }

    // ---- 3. recognized as somebody else: must not log this user on ----
    Logf("--- scenario 3: face recognized as a different user");
    {
        WriteTextFile(kMockUserFile, "someoneelse");
        Session s;
        if (s.Open(sid, true))
        {
            BOOL unused = FALSE;
            s.credential->SetSelected(&unused);
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION ser;
            s.Submit(&ser);
            Check(!s.WaitChanged(5000), "no CredentialsChanged when the recognized face is another user");
            DWORD count = 0;
            DWORD def = 0;
            BOOL autoLogon = FALSE;
            s.provider->GetCredentialCount(&count, &def, &autoLogon);
            Check(autoLogon == FALSE, "no auto logon for a mismatched face");
            const std::string status = Narrow(s.credentialEvents->LastString());
            Logf("      status shown: %s", status.c_str());
            Check(status.find("does not belong") != std::string::npos, "status explains the face does not belong to this account");
            Check(s.Submit(&ser) == CPGSR_NO_CREDENTIAL_NOT_FINISHED, "submit after a mismatch still returns no credential");
            CoTaskMemFree(ser.rgbSerialization);
        }
        else
        {
            Check(false, "scenario 3 could not open a session");
        }
        s.Close();
    }

    // ---- 4. opt-in autostart: any key or click starts the check, selection alone must not ----
    // The harness runs in session 0 with no keyboard, so only the "nothing starts by itself" half is
    // checked here; the key press itself is exercised against the real LogonUI (cp/tests/logonui).
    Logf("--- scenario 4: autostart switch on");
    {
        WriteTextFile(kMockUserFile, userUtf8.c_str());
        WriteTextFile(kAutoStartFile, "1");
        Session s;
        if (s.Open(sid, true))
        {
            BOOL unused = FALSE;
            s.credential->SetSelected(&unused);
            Check(!s.WaitChanged(3000), "with autostart, selecting the tile alone does not start a face check");
            const std::string status = Narrow(s.credentialEvents->LastString());
            Logf("      status shown: %s", status.c_str());
            Check(status.find("any key") != std::string::npos, "status tells the user any key starts the check");
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION ser;
            s.Submit(&ser);
            Check(s.WaitChanged(15000), "the submit arrow still starts the check in autostart mode");
            Check(s.Submit(&ser) == CPGSR_RETURN_CREDENTIAL_FINISHED, "credential is returned");
            CoTaskMemFree(ser.rgbSerialization);
        }
        else
        {
            Check(false, "scenario 4 could not open a session");
        }
        s.Close();
        DeleteFileW(kAutoStartFile);
    }

    // ---- 5. no user array: previous standalone tile ----
    Logf("--- scenario 5: no user array (fallback to the standalone tile)");
    {
        WriteTextFile(kMockUserFile, userUtf8.c_str());
        Session s;
        if (s.Open(sid, false))
        {
            Check(s.count == 1 && s.defaultIndex == 0, "one standalone credential that is the default");
            ICredentialProviderCredential2* c2 = nullptr;
            const HRESULT hr2 = s.credential->QueryInterface(IID_PPV_ARGS(&c2));
            Check(hr2 == E_NOINTERFACE && c2 == nullptr, "standalone credential does not expose ICredentialProviderCredential2");
            if (c2)
            {
                c2->Release();
            }
            BOOL unused = FALSE;
            s.credential->SetSelected(&unused);
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION ser;
            s.Submit(&ser);
            Check(s.WaitChanged(15000), "standalone tile still completes a face check");
            Check(s.Submit(&ser) == CPGSR_RETURN_CREDENTIAL_FINISHED, "standalone tile returns a credential");
            CoTaskMemFree(ser.rgbSerialization);
        }
        else
        {
            Check(false, "scenario 5 could not open a session");
        }
        s.Close();
    }

    Logf("RESULT: %s (%d of %d checks failed)", g_failures == 0 ? "PASS" : "FAIL", g_failures, g_checks);
    if (g_log)
    {
        fclose(g_log);
    }
    CoUninitialize();
    return g_failures == 0 ? 0 : 1;
}
