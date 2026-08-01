// SPDX-FileCopyrightText: 2023 Open Salamander Authors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "precomp.h"

#include "fileio.h"
#include "tardll.h"
#include "tar.h"
#include "gzip/gzip.h"
#include "rpm/rpm.h"

#include "tar.rh"
#include "tar.rh2"
#include "lang\lang.rh"

// TODO: resolve case sensitivity
// TODO: handle multiple files with the same name in one archive
// TODO: finish the output in the RPM viewer (convert dates to a readable format, etc.)
// TODO: clean up viewer deallocations; on error it behaves quite opaquely
// TODO: check tar against the specification to cover as many flags as possible (GNU extensions, etc.)
// TODO: review error messages and where they are used (TAR vs. CPIO)
// TODO: fix error reporting when the stream fails (do not rely on its ErrorNumber, ensure there is always text)
// TODO: handle multi-volume archives
// TODO: support archives with sparse files
// TODO: could links be turned into shortcuts?
// TODO: add LZMA compression to RPM (see flex-32bit-2.5.35-43.88.s390x.rpm sample). It seems rather rarely used, so maybe add it when more people ask...

//
// ****************************************************************************
//
// Declarations and definitions
//
// ****************************************************************************
//

// ConfigVersion: 0 - plugin installation or version released with Servant Salamander 2.0
//                    (without a configuration number)
//                1 - work-in-progress version before Servant Salamander 2.5 beta 1, added TBZ, BZ, BZ2, and RPM
//                2 - work-in-progress version before Servant Salamander 2.5 beta 1, added CPIO (including the *.CPIO viewer)
//                3 - work-in-progress version before Servant Salamander 2.5 beta 1, removed the *.CPIO viewer
//                4 - work-in-progress version before Servant Salamander 2.5 beta 1, added .z archives
//                5 - work-in-progress version before Servant Salamander 2.52 beta 2, added .DEB archives

int ConfigVersion = 0;
#define CURRENT_CONFIG_VERSION 5
const char* CONFIG_VERSION = "Version";

// plugin interface object, its methods are called from Salamander
CPluginInterface PluginInterface;
// portion of CPluginInterface used for the archiver
CPluginInterfaceForArchiver InterfaceForArchiver;
// portion of CPluginInterface used for the viewer
CPluginInterfaceForViewer InterfaceForViewer;

// column width persistence
static const char* CONFIG_COL_LINKTARGET_WIDTH = "Column LinkTarget Width";
static const char* CONFIG_COL_LINKTARGET_FIXEDWIDTH = "Column LinkTarget FixedWidth";
DWORD ColumnLinkTargetWidth = MAKELONG(120, 120);
DWORD ColumnLinkTargetFixedWidth = MAKELONG(0, 0);

// general Salamander interface - valid from plugin start until its termination
CSalamanderGeneralAbstract* SalamanderGeneral = NULL;

// interface for convenient work with files
CSalamanderSafeFileAbstract* SalamanderSafeFile = NULL;

// variable definition for "dbg.h"
CSalamanderDebugAbstract* SalamanderDebug = NULL;

HINSTANCE DLLInstance = NULL; // handle to the SPL - language-independent resources
HINSTANCE HLanguage = NULL;   // handle to the SLG - language-dependent resources

//
// ****************************************************************************
//
// Helper functions
//
// ****************************************************************************
//

// loads a string from the DLL
char* LoadStr(int resID)
{
    return SalamanderGeneral->LoadStr(HLanguage, resID);
}

// combines a resource string with an optional error string
char* LoadErr(int resID, DWORD LastError)
{
    static char buffer[1000];
    strcpy(buffer, LoadStr(resID));
    if (LastError != 0)
        strcat(buffer, SalamanderGeneral->GetErrorText(LastError));
    return buffer;
}

//
// ****************************************************************************
//
// Plugin initialization
//
// ****************************************************************************
//

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        DLLInstance = hinstDLL;
    return TRUE; // DLL can be loaded
}

//
// ****************************************************************************
//
// Functions for communication with Salamander
//
// ****************************************************************************
//

// ****************************************************************************
// SalamanderPluginGetReqVer - returns the required Salamander version
//
int WINAPI SalamanderPluginGetReqVer()
{
    return LAST_VERSION_OF_SALAMANDER;
}

// ****************************************************************************
// SalamanderPluginEntry - main entry point
//
CPluginInterfaceAbstract* WINAPI SalamanderPluginEntry(CSalamanderPluginEntryAbstract* salamander)
{
    // set SalamanderDebug for "dbg.h"
    SalamanderDebug = salamander->GetSalamanderDebug();

    CALL_STACK_MESSAGE1("SalamanderPluginEntry()");

    // this plugin is built for the current Salamander version and newer - perform a check
    if (salamander->GetVersion() < LAST_VERSION_OF_SALAMANDER)
    { // reject older versions
        MessageBox(salamander->GetParentWindow(),
                   REQUIRE_LAST_VERSION_OF_SALAMANDER,
                   "TAR" /* do not translate */, MB_OK | MB_ICONERROR);
        return NULL;
    }

    // let Salamander load the language module (.slg)
    HLanguage = salamander->LoadLanguageModule(salamander->GetParentWindow(), "TAR" /* do not translate */);
    if (HLanguage == NULL)
        return NULL;

    // obtain Salamander's general interface
    SalamanderGeneral = salamander->GetSalamanderGeneral();
    SalamanderSafeFile = salamander->GetSalamanderSafeFile();

    // log a diagnostic message
    TRACE_I("SalamanderPluginEntry called, Salamander version " << salamander->GetVersion());

    // set basic plugin information
    salamander->SetBasicPluginData(LoadStr(IDS_PLUGINNAME),
                                   FUNCTION_LOADSAVECONFIGURATION |
                                       FUNCTION_PANELARCHIVERVIEW | FUNCTION_CUSTOMARCHIVERUNPACK |
                                       FUNCTION_VIEWER,
                                   VERSINFO_VERSION_NO_PLATFORM,
                                   VERSINFO_COPYRIGHT,
                                   LoadStr(IDS_PLUGIN_DESCRIPTION),
                                   "TAR" /* do not translate */, "tar;tgz;taz;tbz;gz;bz;bz2;z;rpm;cpio;deb");

    salamander->SetPluginHomePageURL("www.altap.cz");

    return &PluginInterface;
}

void CPluginInterface::About(HWND parent)
{
    char buf[1000];
    _snprintf_s(buf, _TRUNCATE,
                "%s " VERSINFO_VERSION "\n\n" VERSINFO_COPYRIGHT "\nbzip2 library Copyright © 1996-2010 Julian R Seward\n\n"
                "%s",
                LoadStr(IDS_PLUGINNAME),
                LoadStr(IDS_PLUGIN_DESCRIPTION));
    SalamanderGeneral->SalMessageBox(parent, buf, LoadStr(IDS_ABOUT), MB_OK | MB_ICONINFORMATION);
}

void CPluginInterface::LoadConfiguration(HWND parent, HKEY regKey, CSalamanderRegistryAbstract* registry)
{
    CALL_STACK_MESSAGE1("CPluginInterface::LoadConfiguration(, ,)");
    if (regKey != NULL) // load from the registry
    {
        if (!registry->GetValue(regKey, CONFIG_VERSION, REG_DWORD, &ConfigVersion, sizeof(DWORD)))
        {
            ConfigVersion = 0; // error - use the version without loading
        }
        registry->GetValue(regKey, CONFIG_COL_LINKTARGET_WIDTH, REG_DWORD,
                           &ColumnLinkTargetWidth, sizeof(DWORD));
        registry->GetValue(regKey, CONFIG_COL_LINKTARGET_FIXEDWIDTH, REG_DWORD,
                           &ColumnLinkTargetFixedWidth, sizeof(DWORD));
    }
    else // default configuration
    {
        ConfigVersion = 0; // without loading
    }
}

void CPluginInterface::SaveConfiguration(HWND parent, HKEY regKey, CSalamanderRegistryAbstract* registry)
{
    CALL_STACK_MESSAGE1("CPluginInterface::SaveConfiguration(, ,)");

    DWORD v = CURRENT_CONFIG_VERSION;
    registry->SetValue(regKey, CONFIG_VERSION, REG_DWORD, &v, sizeof(DWORD));
    registry->SetValue(regKey, CONFIG_COL_LINKTARGET_WIDTH, REG_DWORD,
                       &ColumnLinkTargetWidth, sizeof(DWORD));
    registry->SetValue(regKey, CONFIG_COL_LINKTARGET_FIXEDWIDTH, REG_DWORD,
                       &ColumnLinkTargetFixedWidth, sizeof(DWORD));
}

void CPluginInterface::Connect(HWND parent, CSalamanderConnectAbstract* salamander)
{
    CALL_STACK_MESSAGE1("CPluginInterface::Connect()");

    // base part:
    salamander->AddCustomUnpacker("TAR (Plugin)",
                                  "*.tar;*.tgz;*.tbz;*.taz;"
                                  "*.tar.gz;*.tar.bz;*.tar.bz2;*.tar.z;"
                                  "*_tar.gz;*_tar.bz;*_tar.bz2;*_tar.z;"
                                  "*_tar_gz;*_tar_bz;*_tar_bz2;*_tar_z;"
                                  "*.tar_gz;*.tar_bz;*.tar_bz2;*.tar_z;"
                                  "*.gz;*.bz;*.bz2;*.z;"
                                  "*.rpm;*.cpio;*.deb",
                                  ConfigVersion < 5);                                       // ignored during upgrades except when upgrading to version 4 - required update because of "*.z" and others
    salamander->AddPanelArchiver("tgz;tbz;taz;tar;gz;bz;bz2;z;rpm;cpio;deb", FALSE, FALSE); // ignored when upgrading the plugin
    salamander->AddViewer("*.rpm", FALSE);                                                  // ignored when upgrading the plugin except when upgrading from a version without the viewer (the version shipped with SS 2.0)

    // section for upgrades:
    if (ConfigVersion < 1) // 1 - work-in-progress version before Servant Salamander 2.5 beta 1, added tbz, bz, bz2, and rpm
    {
        salamander->AddPanelArchiver("tbz;bz;bz2;rpm", FALSE, TRUE);
    }

    if (ConfigVersion < 2) // 2 - work-in-progress version before Servant Salamander 2.5 beta 1, added cpio (including the *.cpio viewer - that was a mistake)
    {
        salamander->AddPanelArchiver("cpio", FALSE, TRUE);

        // adding *.cpio was a mistake, version 3 removes it again
        //salamander->AddViewer("*.cpio", TRUE);
    }

    /*
  if (ConfigVersion < 3)    // 3 - work-in-progress version before Servant Salamander 2.5 beta 1, removed the *.cpio viewer
  {
    salamander->ForceRemoveViewer("*.cpio");   // comment out once we consider it dead code
  }
*/

    if (ConfigVersion < 4) // 4 - work-in-progress version before Servant Salamander 2.5 beta 1, added .z archives
    {
        salamander->AddPanelArchiver("taz;z", FALSE, TRUE);
    }
    if (ConfigVersion < 5) // 5 - work-in-progress version before Servant Salamander 2.52 beta 2, added .deb archives
    {
        salamander->AddPanelArchiver("deb", FALSE, TRUE);
    }
}

CPluginInterfaceForArchiverAbstract*
CPluginInterface::GetInterfaceForArchiver()
{
    return &InterfaceForArchiver;
}

CPluginInterfaceForViewerAbstract*
CPluginInterface::GetInterfaceForViewer()
{
    return &InterfaceForViewer;
}

void CPluginInterface::ReleasePluginDataInterface(CPluginDataInterfaceAbstract* pluginData)
{
    if (pluginData != NULL)
        delete ((CPluginDataInterface*)pluginData);
}

//
// ****************************************************************************
// CPluginDataInterface
//

// transfer variables for custom column callbacks (see CSalamanderViewAbstract::GetTransferVariables)
static const CFileData** TransferFileData = NULL;
static int* TransferIsDir = NULL;
static char* TransferBuffer = NULL;
static int* TransferLen = NULL;
static DWORD* TransferRowData = NULL;
static CPluginDataInterfaceAbstract** TransferPluginDataIface = NULL;
static DWORD* TransferActCustomData = NULL;

void CPluginDataInterface::ReleasePluginData(CFileData& file, BOOL isDir)
{
    if (file.PluginData != 0)
    {
        delete (CTarLinkData*)file.PluginData;
        file.PluginData = 0;
    }
}

BOOL CPluginDataInterface::GetFileDataForNewDir(const char* dirName, CFileData& dir)
{
    dir.PluginData = 0;
    return TRUE;
}

static void WINAPI GetLinkTargetText()
{
    if (*TransferIsDir == 2) // up-dir symbol
    {
        *TransferLen = 0;
        return;
    }
    if ((*TransferFileData)->PluginData != 0)
    {
        CTarLinkData* ld = (CTarLinkData*)(*TransferFileData)->PluginData;
        if (ld->RawTarget != NULL)
        {
            int len = _snprintf_s(TransferBuffer, 1000, _TRUNCATE, "%s", ld->RawTarget);
            if (len < 0)
                len = 999;
            // append [!] marker for dangling/unresolved symlinks
            if (ld->ResolvedName == NULL)
            {
                int extra = _snprintf_s(TransferBuffer + len, 1000 - len, _TRUNCATE, " [!]");
                if (extra > 0)
                    len += extra;
            }
            *TransferLen = len;
        }
        else
        {
            *TransferLen = 0;
        }
    }
    else
    {
        *TransferLen = 0;
    }
}

void CPluginDataInterface::SetupView(BOOL leftPanel, CSalamanderViewAbstract* view,
                                     const char* archivePath, const CFileData* upperDir)
{
    view->GetTransferVariables(TransferFileData, TransferIsDir, TransferBuffer, TransferLen,
                               TransferRowData, TransferPluginDataIface, TransferActCustomData);

    if (view->GetViewMode() == VIEW_MODE_DETAILED)
    {
        // find and remove the standard Attributes column, remember its position
        int attrIndex = -1;
        int count = view->GetColumnsCount();
        for (int i = 0; i < count; i++)
        {
            if (view->GetColumn(i)->ID == COLUMN_ID_ATTRIBUTES)
            {
                attrIndex = i;
                break;
            }
        }
        if (attrIndex >= 0)
            view->DeleteColumn(attrIndex);
        else
            attrIndex = count; // append at end if Attr wasn't found

        // insert Link Target column at the Attributes column position
        CColumn column;
        lstrcpyn(column.Name, LoadStr(IDS_COL_LINKTARGET), COLUMN_NAME_MAX);
        lstrcpyn(column.Description, LoadStr(IDS_COL_LINKTARGET_DESC), COLUMN_DESCRIPTION_MAX);
        column.GetText = GetLinkTargetText;
        column.SupportSorting = 0;
        column.LeftAlignment = 1;
        column.ID = COLUMN_ID_CUSTOM;
        column.CustomData = 0;
        column.Width = leftPanel ? LOWORD(ColumnLinkTargetWidth) : HIWORD(ColumnLinkTargetWidth);
        column.FixedWidth = leftPanel ? LOWORD(ColumnLinkTargetFixedWidth) : HIWORD(ColumnLinkTargetFixedWidth);
        view->InsertColumn(attrIndex, &column);
    }
}

void CPluginDataInterface::ColumnFixedWidthShouldChange(BOOL leftPanel, const CColumn* column, int newFixedWidth)
{
    if (column->CustomData == 0)
    {
        if (leftPanel)
            ColumnLinkTargetFixedWidth = MAKELONG(newFixedWidth, HIWORD(ColumnLinkTargetFixedWidth));
        else
            ColumnLinkTargetFixedWidth = MAKELONG(LOWORD(ColumnLinkTargetFixedWidth), newFixedWidth);
    }
    if (newFixedWidth)
        ColumnWidthWasChanged(leftPanel, column, column->Width);
}

void CPluginDataInterface::ColumnWidthWasChanged(BOOL leftPanel, const CColumn* column, int newWidth)
{
    if (column->CustomData == 0)
    {
        if (leftPanel)
            ColumnLinkTargetWidth = MAKELONG(newWidth, HIWORD(ColumnLinkTargetWidth));
        else
            ColumnLinkTargetWidth = MAKELONG(LOWORD(ColumnLinkTargetWidth), newWidth);
    }
}

//
// ****************************************************************************
//
// Operational functions provided by the plugin
//
// ****************************************************************************
//

BOOL CPluginInterfaceForArchiver::ListArchive(CSalamanderForOperationsAbstract* salamander,
                                              const char* fileName,
                                              CSalamanderDirectoryAbstract* dir,
                                              CPluginDataInterfaceAbstract*& pluginData)
{
    CALL_STACK_MESSAGE2("CPluginInterfaceForArchiver::ListArchive(, %s, ,)", fileName);

    // create the archive object
    CArchiveAbstract* archive = CreateArchive(fileName, salamander);
    // and list it
    if (archive)
    {
        BOOL ret = archive->ListArchive(NULL, dir);
        delete archive;
        if (ret)
		{
            pluginData = new CPluginDataInterface();
            return ret;
		}
    }
    pluginData = NULL;
    return FALSE;
}

// Symlink redirect entry collected during extraction enumeration
struct SymlinkRedir
{
    char curName[2 * MAX_PATH];    // name from enumeration (relative to archiveRoot)
    char resolved[2 * MAX_PATH];   // full archive path of resolved target
    BOOL isDir;                    // TRUE if the entry is a directory (symlink to dir)
};

// Context for the wrapper enumeration callback
struct SymlinkRedirectContext
{
    SalEnumSelection origNext;
    void* origParam;
    SymlinkRedir* entries;
    int count;
    int cap;
};

// Wrapper callback that intercepts the selection enumeration to collect symlink redirect info
static const char* WINAPI WrappedEnumSelection(HWND parent, int enumFiles, BOOL* isDir,
                                               CQuadWord* size, const CFileData** fileData,
                                               void* param, int* errorOccured)
{
    SymlinkRedirectContext* ctx = (SymlinkRedirectContext*)param;

    // Always request fileData from the original callback
    const CFileData* fd = NULL;
    const char* name = ctx->origNext(parent, enumFiles, isDir, size, &fd, ctx->origParam, errorOccured);

    // Forward fileData to caller if they requested it
    if (fileData != NULL)
        *fileData = fd;

    // Collect symlink redirect info for entries that have ResolvedName
    if (name != NULL && fd != NULL && fd->PluginData != 0 && ctx->entries != NULL)
    {
        CTarLinkData* ld = (CTarLinkData*)fd->PluginData;
        if (ld->ResolvedName != NULL)
        {
            if (ctx->count >= ctx->cap)
            {
                ctx->cap *= 2;
                SymlinkRedir* tmp = (SymlinkRedir*)realloc(ctx->entries, ctx->cap * sizeof(SymlinkRedir));
                if (tmp != NULL)
                    ctx->entries = tmp;
            }
            if (ctx->count < ctx->cap)
            {
                SymlinkRedir* e = &ctx->entries[ctx->count];
                strncpy_s(e->curName, name, _TRUNCATE);
                strncpy_s(e->resolved, ld->ResolvedName, _TRUNCATE);
                e->isDir = (isDir != NULL) ? *isDir : FALSE;
                ctx->count++;
            }
        }
    }

    return name;
}

BOOL CPluginInterfaceForArchiver::UnpackArchive(CSalamanderForOperationsAbstract* salamander,
                                                const char* fileName, CPluginDataInterfaceAbstract* pluginData,
                                                const char* targetDir, const char* archiveRoot,
                                                SalEnumSelection next, void* nextParam)
{
    CALL_STACK_MESSAGE4("CPluginInterfaceForArchiver::UnpackArchive(, %s, , %s, %s,,,)",
                        fileName, targetDir, archiveRoot);

    // Setup wrapper callback to intercept enumeration and collect symlink info
    SymlinkRedirectContext ctx;
    ctx.origNext = next;
    ctx.origParam = nextParam;
    ctx.count = 0;
    ctx.cap = 32;
    ctx.entries = (SymlinkRedir*)malloc(ctx.cap * sizeof(SymlinkRedir));

    // Normal batch extraction with wrapper callback
    // (regular files extract normally; symlink entries extract as 0-byte since they
    // have no data in the archive; mirror entries inside dir symlinks won't match
    // any archive entry and will be silently skipped)
    CArchiveAbstract* archive = CreateArchive(fileName, salamander);
    BOOL ret = FALSE;
    if (archive)
    {
        ret = archive->UnpackArchive(targetDir, archiveRoot, WrappedEnumSelection, &ctx);
        delete archive;
    }

    TRACE_I("UnpackArchive: wrapper collected " << ctx.count << " redirect entries, batch ret=" << ret);

    // Re-extract entries that need redirection (symlinks and mirror entries)
    for (int i = 0; i < ctx.count && ret; i++)
    {
        SymlinkRedir* e = &ctx.entries[i];
        TRACE_I("UnpackArchive redirect [" << i << "]: curName='" << e->curName
                << "' resolved='" << e->resolved << "' isDir=" << e->isDir);

        // Build path to the placeholder created by batch extraction
        char emptyPath[2 * MAX_PATH];
        strcpy_s(emptyPath, targetDir);
        if (emptyPath[strlen(emptyPath) - 1] != '\\')
            strcat_s(emptyPath, "\\");
        strcat_s(emptyPath, e->curName);

        if (e->isDir)
        {
            // Directory symlink: remove the 0-byte placeholder file first,
            // then extract the entire resolved target directory tree
            // with paths remapped from the target dir name to the symlink dir name
            SetFileAttributesA(emptyPath, FILE_ATTRIBUTE_NORMAL);
            DeleteFileA(emptyPath);

            CArchiveAbstract* arch2 = CreateArchive(fileName, salamander);
            if (arch2)
            {
                arch2->UnpackDirRedirected(e->resolved, targetDir, e->curName);
                delete arch2;
            }
        }
        else
        {
            // File symlink or mirror entry: delete any 0-byte placeholder file,
            // then extract the resolved target's data with the original output name
            SetFileAttributesA(emptyPath, FILE_ATTRIBUTE_NORMAL);
            DeleteFileA(emptyPath);

            CArchiveAbstract* arch2 = CreateArchive(fileName, salamander);
            if (arch2)
            {
                BOOL oneRet = arch2->UnpackOneFile(e->resolved, NULL, targetDir, e->curName);
                TRACE_I("UnpackArchive redirect [" << i << "]: UnpackOneFile returned " << oneRet);
                delete arch2;
            }
        }
    }

    free(ctx.entries);
    return ret;
}

BOOL CPluginInterfaceForArchiver::UnpackOneFile(CSalamanderForOperationsAbstract* salamander,
                                                const char* fileName, CPluginDataInterfaceAbstract* pluginData,
                                                const char* nameInArchive, const CFileData* fileData,
                                                const char* targetDir, const char* newFileName,
                                                BOOL* renamingNotSupported)
{
    CALL_STACK_MESSAGE4("CPluginInterfaceForArchiver::UnpackOneFile(, %s, , %s, , %s, ,)",
                        fileName, nameInArchive, targetDir);

    // if this is a symlink, redirect to the resolved target
    const char* actualName = nameInArchive;
    const char* actualNewFileName = newFileName;
    if (fileData != NULL && fileData->PluginData != 0)
    {
        CTarLinkData* ld = (CTarLinkData*)fileData->PluginData;
        if (ld->ResolvedName != NULL)
        {
            actualName = ld->ResolvedName;
            // When newFileName is NULL (normal F3 view), the extraction would use the
            // TARGET's filename. We need the SYMLINK's filename instead.
            if (actualNewFileName == NULL)
            {
                const char* baseName = strrchr(nameInArchive, '\\');
                actualNewFileName = baseName ? baseName + 1 : nameInArchive;
            }
        }
        else if (ld->RawTarget != NULL)
        {
            // dangling symlink — show error
            char msg[2 * MAX_PATH];
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, LoadStr(IDS_ERR_DANGLING_SYMLINK), ld->RawTarget);
            SalamanderGeneral->ShowMessageBox(msg, LoadStr(IDS_TARERR_TITLE), MSGBOX_ERROR);
            return FALSE;
        }
    }

    // create the archive object
    CArchiveAbstract* archive = CreateArchive(fileName, salamander);
    // and extract it
    if (archive)
    {
        BOOL ret = archive->UnpackOneFile(actualName, fileData, targetDir, actualNewFileName);
        delete archive;
        return ret;
    }
    return FALSE;
}

BOOL CPluginInterfaceForArchiver::UnpackWholeArchive(CSalamanderForOperationsAbstract* salamander,
                                                     const char* fileName, const char* mask,
                                                     const char* targetDir, BOOL delArchiveWhenDone,
                                                     CDynamicString* archiveVolumes)
{
    CALL_STACK_MESSAGE5("CPluginInterfaceForArchiver::UnpackWholeArchive(, %s, %s, %s, %d,)",
                        fileName, mask, targetDir, delArchiveWhenDone);

    // create the archive object
    CArchiveAbstract* archive = CreateArchive(fileName, salamander);
    // and extract it
    if (archive)
    {
        if (delArchiveWhenDone)
            archiveVolumes->Add(fileName, -2); // FIXME: once the plugin learns multi-volume archives, add all volumes here (so the entire archive gets deleted)
        BOOL ret = archive->UnpackWholeArchive(mask, targetDir);
        delete archive;
        return ret;
    }
    return FALSE;
}

/*
BOOL
CPluginInterfaceForArchiver::PackToArchive(CSalamanderForOperationsAbstract *salamander,
                                           const char *fileName, const char *archiveRoot,
                                           BOOL move, const char *sourcePath,
                                           SalEnumSelection2 next, void *nextParam)
{
  CALL_STACK_MESSAGE5("CPluginInterfaceForArchiver::PackToArchive(, %s, %s, %d, %s,,)",
                      fileName, archiveRoot, move, sourcePath);
  return FALSE;
}

BOOL
CPluginInterfaceForArchiver::DeleteFromArchive(CSalamanderForOperationsAbstract *salamander,
                                               const char *fileName, CPluginDataInterfaceAbstract *pluginData,
                                               const char *archiveRoot, SalEnumSelection next,
                                               void *nextParam)
{
  CALL_STACK_MESSAGE3("CPluginInterfaceForArchiver::DeleteFromArchive(, %s, , %s, ,)",
                      fileName, archiveRoot);
  return FALSE;
}
*/

// function for the "file viewer"; called when the viewer should open and load a file
// 'name', 'left'+'right'+'width'+'height'+'showCmd'+'alwaysOnTop' is the recommended window placement
// if 'returnUnlock' is FALSE, 'unlock'+'unlockOwner' have no meaning
// if 'returnUnlock' is TRUE, the viewer should return the system event 'unlock'
// in the non-signaled state; it transitions to the signaled state when viewing
// the file 'name' finishes (the file is removed from the temporary directory at that time). It should also
// return TRUE in 'unlockOwner' if the caller should close the 'unlock' object (FALSE means
// the viewer closes 'unlock' itself); if the viewer does not set 'unlock' (stays NULL)
// the file 'name' is valid only until this ViewFile call ends. If
// 'viewerData' is not NULL, it passes extended parameters to the viewer (see
// CSalamanderGeneralAbstract::ViewFileInPluginViewer). Returns TRUE on success
// (FALSE indicates failure; 'unlock' and 'unlockOwner' have no meaning in that case)
BOOL CPluginInterfaceForViewer::ViewFile(const char* name, int left, int top, int width, int height,
                                         UINT showCmd, BOOL alwaysOnTop, BOOL returnUnlock, HANDLE* unlock,
                                         BOOL* unlockOwner, CSalamanderPluginViewerData* viewerData,
                                         int enumFilesSourceUID, int enumFilesCurrentIndex)
{
    CALL_STACK_MESSAGE11("CPluginInterfaceForViewer::ViewFile(%s, %d, %d, %d, %d, "
                         "0x%X, %d, %d, , , , %d, %d)",
                         name, left, top, width, height,
                         showCmd, alwaysOnTop, returnUnlock, enumFilesSourceUID, enumFilesCurrentIndex);

    // unlock stays NULL, we do not need locking
    //   therefore we also ignore returnUnlock and unlockOwner
    // viewerData is not used

    // store the original cursor and show the hourglass (even though it should not take long...)
    HCURSOR hOldCur = SetCursor(LoadCursor(NULL, IDC_WAIT));

    // open the input file
    HANDLE file = CreateFile(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                             FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        int err = GetLastError();
        SetCursor(hOldCur);
        SalamanderGeneral->ShowMessageBox(LoadErr(IDS_GZERR_FOPEN, err),
                                          LoadStr(IDS_GZERR_TITLE), MSGBOX_ERROR);
        return FALSE;
    }
    // allocate a buffer for reading the file
    unsigned char* buffer = (unsigned char*)malloc(BUFSIZE);
    if (buffer == NULL)
    {
        SetCursor(hOldCur);
        SalamanderGeneral->ShowMessageBox(LoadStr(IDS_ERR_MEMORY), LoadStr(IDS_GZERR_TITLE),
                                          MSGBOX_ERROR);
        CloseHandle(file);
        return FALSE;
    }
    // read the first block of data
    DWORD read;
    if (!ReadFile(file, buffer, BUFSIZE, &read, NULL))
    {
        // read error
        int err = GetLastError();
        SetCursor(hOldCur);
        free(buffer);
        CloseHandle(file);
        SalamanderGeneral->ShowMessageBox(LoadErr(IDS_ERR_FREAD, err), LoadStr(IDS_GZERR_TITLE), MSGBOX_ERROR);
        return FALSE;
    }
    // obtain a name for the temporary text file with the results
    char tempFileName[MAX_PATH];
    if (!SalamanderGeneral->SalGetTempFileName(NULL, "RPV", tempFileName, TRUE, NULL))
    {
        SetCursor(hOldCur);
        free(buffer);
        CloseHandle(file);
        SalamanderGeneral->ShowMessageBox(LoadStr(IDS_RPMERR_TMPNAME), LoadStr(IDS_ERR_RPMTITLE), MSGBOX_ERROR);
        return FALSE;
    }

    // create the temporary file
    FILE* fContents = fopen(tempFileName, "wt");
    if (fContents == NULL)
    {
        char buff[500];
        SetCursor(hOldCur);
        free(buffer);
        CloseHandle(file);
        buff[499] = '\0';
        strcpy(buff, LoadStr(IDS_RPMERR_TMPFILE));
        strncat(buff, name, 499 - strlen(buff));
        SalamanderGeneral->ShowMessageBox(buff, LoadStr(IDS_ERR_RPMTITLE), MSGBOX_ERROR);
        return FALSE;
    }
    // create the RPM object and fill the temporary file with information
    CDecompressFile* archive = new CRPM(name, file, buffer, read, fContents);
    if (archive == NULL)
    {
        SetCursor(hOldCur);
        fclose(fContents);
        DeleteFile(tempFileName);
        free(buffer);
        CloseHandle(file);
        SalamanderGeneral->ShowMessageBox(LoadStr(IDS_ERR_MEMORY), LoadStr(IDS_ERR_RPMTITLE), MSGBOX_ERROR);
        return FALSE;
    }
    // TODO: probably make sure errors are not reported inside and only a flag is set according to the error
    if (!archive->IsOk())
    {
        SetCursor(hOldCur);
        fclose(fContents);
        DeleteFile(tempFileName);
        free(buffer);
        CloseHandle(file);
        if (archive->GetErrorCode() == 0)
            SalamanderGeneral->ShowMessageBox(LoadStr(IDS_ERR_NORPM), LoadStr(IDS_ERR_RPMTITLE), MSGBOX_ERROR);
        else
            SalamanderGeneral->ShowMessageBox(LoadStr(archive->GetErrorCode()),
                                              LoadStr(IDS_ERR_RPMTITLE), MSGBOX_ERROR);
        delete archive;
        return FALSE;
    }
    // now we can close the archive again...
    // the input file and buffer are cleaned up in the CDecompressFile destructor
    delete archive;
    // done
    fclose(fContents);

    // prepare the structure for Salamander's text viewer
    CSalamanderPluginInternalViewerData textViewerData;
    textViewerData.Size = sizeof(textViewerData);
    textViewerData.FileName = tempFileName;
    textViewerData.Mode = 0; // text mode
    char caption[500];
    strncpy_s(caption, 451, name, _TRUNCATE);
    strcat(caption, " - ");
    strcat(caption, LoadStr(IDS_RPM_VIEWTITLE));
    textViewerData.Caption = caption;
    textViewerData.WholeCaption = TRUE;
    // show the file in Salamander's text viewer and delete it afterwards
    int err;
    SalamanderGeneral->ViewFileInPluginViewer(NULL, &textViewerData, TRUE, NULL, "rpm_dump.txt", err);

    // and finally clean up
    SetCursor(hOldCur);
    return TRUE;
}
