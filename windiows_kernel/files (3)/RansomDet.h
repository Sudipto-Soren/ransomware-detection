/*
 * RansomDet.h
 * Shared between the kernel driver and the user-mode monitor service.
 *
 * This header defines the event structure that flows from kernel space
 * to user space every time a file operation is intercepted.
 * It must be identical on both sides of the communication.
 */

#pragma once

/* ── Communication port name ─────────────────────────────────────────────────
 * The driver creates this port. The user-mode monitor connects to it.
 * Think of it as a named socket between kernel and user space.
 */
#define RANSOMDET_PORT_NAME     L"\\RansomDetPort"

/* ── Maximum path length we capture ─────────────────────────────────────────
 * 260 = MAX_PATH on Windows. Longer paths are truncated.
 */
#define RANSOMDET_MAX_PATH      260
#define RANSOMDET_MAX_PROCNAME  64

/* ── Operation codes ─────────────────────────────────────────────────────────
 * Matches the "operation" field in docs/event-schema.json.
 */
#define OP_CREATE               0
#define OP_WRITE                1
#define OP_RENAME               2
#define OP_DELETE               3
#define OP_SET_INFO             4

/* ── Event structure ─────────────────────────────────────────────────────────
 * One of these is sent to user mode per intercepted file operation.
 * Keep fields aligned to 4 bytes to avoid padding surprises across
 * kernel/user boundary.
 */
typedef struct _RANSOMDET_EVENT {
    ULONG         Operation;                        // OP_CREATE / OP_WRITE / etc.
    ULONG         ProcessId;
    WCHAR         ProcessName[RANSOMDET_MAX_PROCNAME]; // e.g. notepad.exe
    WCHAR         FilePath[RANSOMDET_MAX_PATH];     // target file
    WCHAR         NewFilePath[RANSOMDET_MAX_PATH];  // destination path (rename only)
    LONGLONG      Timestamp;                        // FILETIME: 100-ns ticks since 1601
    ULONGLONG     FileSize;                         // bytes (0 if unavailable)
} RANSOMDET_EVENT, *PRANSOMDET_EVENT;

/* ── Message wrapper ─────────────────────────────────────────────────────────
 * FltSendMessage / FilterGetMessage require a FILTER_MESSAGE_HEADER
 * prepended to your payload. This struct bundles both together so
 * the user-mode code can cast a single buffer.
 */
#pragma pack(push, 1)
typedef struct _RANSOMDET_MESSAGE {
    FILTER_MESSAGE_HEADER Header;   // filled in by the filter manager
    RANSOMDET_EVENT       Event;    // our payload
} RANSOMDET_MESSAGE, *PRANSOMDET_MESSAGE;
#pragma pack(pop)
