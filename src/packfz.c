/*
 * PackCC: a packrat parser generator for C.
 *
 * Copyright (c) 2014, 2019-2024 Arihiro Yoshida. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * The algorithm is based on the paper "Packrat Parsers Can Support Left Recursion"
 * authored by A. Warth, J. R. Douglass, and T. Millstein.
 *
 * The specification is determined by referring to peg/leg developed by Ian Piumarta.
 */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#ifndef _MSC_VER
#if defined __GNUC__ && defined _WIN32 /* MinGW */
#ifndef PCC_USE_SYSTEM_STRNLEN
#define strnlen(str, maxlen) strnlen_(str, maxlen)
static size_t strnlen_(const char *str, size_t maxlen) {
    size_t i;
    for (i = 0; i < maxlen && str[i]; i++);
    return i;
}
#endif /* !PCC_USE_SYSTEM_STRNLEN */
#endif /* defined __GNUC__ && defined _WIN32 */
#endif /* !_MSC_VER */

#ifdef _MSC_VER
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define unlink _unlink
#else
#include <unistd.h> /* for unlink() */
#endif

#ifdef _WIN32 /* Windows including MSVC and MinGW */
#include <io.h> /* _get_osfhandle() */
/* NOTE: The header "fileapi.h" causes a compiler error due to an illegal anonymous union. */
#define DECLSPEC_IMPORT __declspec(dllimport)
#define WINAPI __stdcall
#define S_OK 0
#define CSIDL_PROFILE 0x0028
#define CSIDL_COMMON_APPDATA 0x0023
#define SHGFP_TYPE_DEFAULT 1
#define MAX_PATH 260
typedef int BOOL;
typedef unsigned long DWORD;
typedef char *LPSTR;
typedef long HRESULT;
typedef void *HANDLE;
typedef void *HWND;
typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;
typedef struct _BY_HANDLE_FILE_INFORMATION {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *LPBY_HANDLE_FILE_INFORMATION;
DECLSPEC_IMPORT BOOL WINAPI GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);
DECLSPEC_IMPORT HRESULT WINAPI SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);
#else /* !_WIN32 */
#include <sys/stat.h> /* for fstat() */
#endif

#if !defined __has_attribute || defined _MSC_VER
#define __attribute__(x)
#endif

#undef TRUE  /* to avoid macro definition conflicts with the system header file of IBM AIX */
#undef FALSE

#ifdef _MSC_VER
#define IMPORT_DIR_SYSTEM "packcc/import" /* should be a relative path */
#else
#define IMPORT_DIR_SYSTEM "/usr/share/packcc/import" /* should be an absolute path */
#endif

#define IMPORT_DIR_USER ".packcc/import"

#ifdef _WIN32 /* Windows including MSVC and MinGW (MinGW automatically converts paths to those in Windows style) */
#define PATH_SEP ';'
#else
#define PATH_SEP ':'
#endif

#define ENVVAR_IMPORT_PATH "PCC_IMPORT_PATH"

#define WEBSITE "https://github.com/arithy/packcc"

#define VERSION "2.0.3"

#ifndef BUFFER_MIN_SIZE
#define BUFFER_MIN_SIZE 256
#endif
#ifndef ARRAY_MIN_SIZE
#define ARRAY_MIN_SIZE 2
#endif

#define VOID_VALUE (~(size_t)0)

#ifdef _WIN64 /* 64-bit Windows including MSVC and MinGW-w64 */
#define FMT_LU "%llu"
typedef unsigned long long ulong_t;
/* NOTE: "%llu" and "long long" are not C89-compliant, but we cannot help using them to deal with a 64-bit integer value in 64-bit Windows. */
#else
#define FMT_LU "%lu"
typedef unsigned long ulong_t;
#endif
/* FMT_LU and ulong_t are used to print size_t values safely (ex. printf(FMT_LU "\n", (ulong_t)value);) */
/* NOTE: Neither "%zu" nor <inttypes.h> is used since PackCC complies with the C89 standard as much as possible. */

typedef enum bool_tag {
    FALSE = 0,
    TRUE
} bool_t;

#ifdef _WIN32 /* Windows including MSVC and MinGW */
typedef BY_HANDLE_FILE_INFORMATION file_id_t;
#else
typedef struct stat file_id_t;
#endif

typedef struct file_id_array_tag {
    file_id_t *buf;
    size_t max;
    size_t len;
} file_id_array_t;

typedef struct file_pos_tag {
    char *path;  /* the file path name */
    size_t line; /* the line number (0-based); VOID_VALUE if not available */
    size_t col;  /* the column number (0-based); VOID_VALUE if not available */
} file_pos_t;

typedef struct stream_tag {
    FILE *file;       /* the file stream; just a reference */
    const char *path; /* the file path name */
    size_t line;      /* the current line number (0-based); line counting is disabled if VOID_VALUE */
} stream_t;

typedef struct char_array_tag {
    char *buf;
    size_t max;
    size_t len;
} char_array_t;

typedef struct string_array_tag {
    char **buf;
    size_t max;
    size_t len;
} string_array_t;

typedef struct code_block_tag {
    char *text;
    size_t len;
    file_pos_t fpos;
} code_block_t;

typedef struct code_block_array_tag {
    code_block_t *buf;
    size_t max;
    size_t len;
} code_block_array_t;

typedef enum node_type_tag {
    NODE_RULE = 0,
    NODE_REFERENCE,
    NODE_STRING,
    NODE_CHARCLASS,
    NODE_QUANTITY,
    NODE_PREDICATE,
    NODE_SEQUENCE,
    NODE_ALTERNATE,
    NODE_CAPTURE,
    NODE_EXPAND,
    NODE_ACTION,
    NODE_ERROR
} node_type_t;

typedef struct node_tag node_t;

typedef struct node_array_tag {
    node_t **buf;
    size_t max;
    size_t len;
} node_array_t;

typedef struct node_const_array_tag {
    const node_t **buf;
    size_t max;
    size_t len;
} node_const_array_t;

typedef struct node_hash_table_tag {
    const node_t **buf;
    size_t max;
    size_t mod;
} node_hash_table_t;

typedef struct node_rule_tag {
    char *name;
    node_t *expr;
    int ref; /* mutable under make_rulehash(), link_references(), and unreference_rules_from_unused_rule() */
    bool_t used; /* mutable under mark_rules_if_used() */
    node_const_array_t vars;
    node_const_array_t capts;
    node_const_array_t codes;
    file_pos_t fpos;
} node_rule_t;

typedef struct node_reference_tag {
    char *var; /* NULL if no variable name */
    size_t index;
    char *name;
    const node_t *rule;
    file_pos_t fpos;
} node_reference_t;

typedef struct node_string_tag {
    char *value;
} node_string_t;

typedef struct node_charclass_tag {
    char *value; /* NULL means any character */
} node_charclass_t;

typedef struct node_quantity_tag {
    int min;
    int max;
    node_t *expr;
} node_quantity_t;

typedef struct node_predicate_tag {
    bool_t neg;
    node_t *expr;
} node_predicate_t;

typedef struct node_sequence_tag {
    node_array_t nodes;
} node_sequence_t;

typedef struct node_alternate_tag {
    node_array_t nodes;
} node_alternate_t;

typedef struct node_capture_tag {
    node_t *expr;
    size_t index;
} node_capture_t;

typedef struct node_expand_tag {
    size_t index;
    file_pos_t fpos;
} node_expand_t;

typedef struct node_action_tag {
    code_block_t code;
    size_t index;
    node_const_array_t vars;
    node_const_array_t capts;
} node_action_t;

typedef struct node_error_tag {
    node_t *expr;
    code_block_t code;
    size_t index;
    node_const_array_t vars;
    node_const_array_t capts;
} node_error_t;

typedef union node_data_tag {
    node_rule_t      rule;
    node_reference_t reference;
    node_string_t    string;
    node_charclass_t charclass;
    node_quantity_t  quantity;
    node_predicate_t predicate;
    node_sequence_t  sequence;
    node_alternate_t alternate;
    node_capture_t   capture;
    node_expand_t    expand;
    node_action_t    action;
    node_error_t     error;
} node_data_t;

struct node_tag {
    node_type_t type;
    node_data_t data;
};

typedef struct options_tag {
    bool_t ascii; /* UTF-8 support is disabled if true  */
    bool_t lines; /* #line directives are output if true */
    bool_t debug; /* debug information is output if true */
    /* randomly pick one option instead of enumerating all possible outputs 
       (applies to CHARCLASS, QUANTITY, ALTERNATE)*/
    bool_t stochastic; 
    int maxdepth; // maximum depth to recurse to while expanding the grammar
    int maxstar; // maximum number of times a *'d rule will be expanded 
    int minlen; // minimum length of fuzzed output to print
} options_t;

typedef enum code_flag_tag {
    CODE_FLAG__NONE = 0,
    CODE_FLAG__UTF8_CHARCLASS_USED = 1
} code_flag_t;

typedef struct input_state_tag input_state_t;

struct input_state_tag {
    char *path;        /* the path name of the PEG file being parsed; "<stdin>" if stdin */
    FILE *file;        /* the input file stream of the PEG file */
    bool_t ascii;      /* UTF-8 support is disabled if true  */
    code_flag_t flags; /* the bitwise flags to control code generation; updated during PEG parsing */
    size_t errnum;     /* the current number of PEG parsing errors */
    size_t linenum;    /* the current line number (0-based) */
    size_t charnum;    /* the number of characters in the current line that are already flushed (0-based, UTF-8 support if not disabled) */
    size_t linepos;    /* the beginning position in the PEG file of the current line */
    size_t bufpos;     /* the position in the PEG file of the first character currently buffered */
    size_t bufcur;     /* the current parsing position in the character buffer */
    char_array_t buffer;   /* the character buffer */
    input_state_t *parent; /* the input state of the parent PEG file that imports the input; just a reference */
};

typedef struct context_tag {
    char *spath;  /* the path name of the C source file being generated */
    char *hpath;  /* the path name of the C header file being generated */
    char *hid;    /* the macro name for the include guard of the C header file */
    char *vtype;  /* the type name of the data output by the parsing API function (NULL means the default) */
    char *atype;  /* the type name of the user-defined data passed to the parser creation API function (NULL means the default) */
    char *prefix; /* the prefix of the API function names (NULL means the default) */
    const string_array_t *dirs; /* the path names of directories to search for import files */
    options_t opts;       /* the options */
    code_flag_t flags;    /* the bitwise flags to control code generation; updated during PEG parsing */
    size_t errnum;        /* the current number of PEG parsing errors */
    input_state_t *input; /* the current input state */
    file_id_array_t done; /* the unique identifiers of the PEG file already parsed or being parsed */
    node_array_t rules;   /* the PEG rules */
    node_hash_table_t rulehash; /* the hash table to accelerate access of desired PEG rules */
    code_block_array_t esource; /* the code blocks from %earlysource and %earlycommon directives to be added into the generated source file */
    code_block_array_t eheader; /* the code blocks from %earlyheader and %earlycommon directives to be added into the generated header file */
    code_block_array_t source;  /* the code blocks from %source and %common directives to be added into the generated source file */
    code_block_array_t header;  /* the code blocks from %header and %common directives to be added into the generated header file */
    code_block_array_t fsource; /* the code fragments after %% directive to be added into the generated source file */
} context_t;

typedef struct generate_tag {
    stream_t *stream;
    const node_t *rule;
    int label;
    bool_t ascii;
} generate_t;

typedef enum string_flag_tag {
    STRING_FLAG__NONE = 0,
    STRING_FLAG__NOTEMPTY = 1,
    STRING_FLAG__NOTVOID = 2,
    STRING_FLAG__IDENTIFIER = 4
} string_flag_t;

typedef enum code_reach_tag {
    CODE_REACH__BOTH = 0,
    CODE_REACH__ALWAYS_SUCCEED = 1,
    CODE_REACH__ALWAYS_FAIL = -1
} code_reach_t;

static const char *g_cmdname = "packcc"; /* replaced later with actual one */

__attribute__((format(printf, 1, 2)))
static int print_error(const char *format, ...) {
    int n;
    va_list a;
    va_start(a, format);
    n = fprintf(stderr, "%s: ", g_cmdname);
    if (n >= 0) {
        const int k = vfprintf(stderr, format, a);
        if (k < 0) n = k; else n += k;
    }
    va_end(a);
    return n;
}

static FILE *fopen_rb_e(const char *path) {
    FILE *const f = fopen(path, "rb");
    if (f == NULL) {
        print_error("Cannot open file to read: %s\n", path);
        exit(2);
    }
    return f;
}

static FILE *fopen_wt_e(const char *path) {
    FILE *const f = fopen(path, "wt");
    if (f == NULL) {
        print_error("Cannot open file to write: %s\n", path);
        exit(2);
    }
    return f;
}

static int fclose_e(FILE *file, const char *path) {
    const int r = fclose(file);
    if (r == EOF) {
        print_error("File closing error: %s\n", path);
        exit(2);
    }
    return r;
}

static int fgetc_e(FILE *file, const char *path) {
    const int c = fgetc(file);
    if (c == EOF && ferror(file)) {
        print_error("File read error: %s\n", path);
        exit(2);
    }
    return c;
}

static void *malloc_e(size_t size) {
    void *const p = malloc(size);
    if (p == NULL) {
        print_error("Out of memory\n");
        exit(3);
    }
    return p;
}

static void *realloc_e(void *ptr, size_t size) {
    void *const p = realloc(ptr, size);
    if (p == NULL) {
        print_error("Out of memory\n");
        exit(3);
    }
    return p;
}

static char *strdup_e(const char *str) {
    const size_t m = strlen(str);
    char *const s = (char *)malloc_e(m + 1);
    memcpy(s, str, m);
    s[m] = '\0';
    return s;
}

static char *strndup_e(const char *str, size_t len) {
    const size_t m = strnlen(str, len);
    char *const s = (char *)malloc_e(m + 1);
    memcpy(s, str, m);
    s[m] = '\0';
    return s;
}

static size_t string_to_size_t(const char *str) {
#define N (~(size_t)0 / 10)
#define M (~(size_t)0 - 10 * N)
    size_t n = 0, i, k;
    for (i = 0; str[i]; i++) {
        const char c = str[i];
        if (c < '0' || c > '9') return VOID_VALUE;
        k = (size_t)(c - '0');
        if (n >= N && k > M) return VOID_VALUE; /* overflow */
        n = k + 10 * n;
    }
    return n;
#undef N
#undef M
}

static size_t find_first_trailing_space(const char *str, size_t start, size_t end, size_t *next) {
    size_t j = start, i;
    for (i = start; i < end; i++) {
        switch (str[i]) {
        case ' ':
        case '\v':
        case '\f':
        case '\t':
            continue;
        case '\n':
            if (next) *next = i + 1;
            return j;
        case '\r':
            if (i + 1 < end && str[i + 1] == '\n') i++;
            if (next) *next = i + 1;
            return j;
        default:
            j = i + 1;
        }
    }
    if (next) *next = end;
    return j;
}

static size_t count_indent_spaces(const char *str, size_t start, size_t end, size_t *next) {
    size_t n = 0, i;
    for (i = start; i < end; i++) {
        switch (str[i]) {
        case ' ':
        case '\v':
        case '\f':
            n++;
            break;
        case '\t':
            n = (n + 8) & ~7;
            break;
        default:
            if (next) *next = i;
            return n;
        }
    }
    if (next) *next = end;
    return n;
}

static bool_t is_filled_string(const char *str) {
    size_t i;
    for (i = 0; str[i]; i++) {
        if (
            str[i] != ' '  &&
            str[i] != '\v' &&
            str[i] != '\f' &&
            str[i] != '\t' &&
            str[i] != '\n' &&
            str[i] != '\r'
        ) return TRUE;
    }
    return FALSE;
}

static bool_t is_identifier_string(const char *str) {
    size_t i;
    if (!(
        (str[0] >= 'a' && str[0] <= 'z') ||
        (str[0] >= 'A' && str[0] <= 'Z') ||
        str[0] == '_'
    )) return FALSE;
    for (i = 1; str[i]; i++) {
        if (!(
            (str[i] >= 'a' && str[i] <= 'z') ||
            (str[i] >= 'A' && str[i] <= 'Z') ||
            (str[i] >= '0' && str[i] <= '9') ||
            str[i] == '_'
        )) return FALSE;
    }
    return TRUE;
}

static bool_t is_pointer_type(const char *str) {
    const size_t n = strlen(str);
    return (n > 0 && str[n - 1] == '*') ? TRUE : FALSE;
}

static bool_t is_valid_utf8_string(const char *str) {
    int k = 0, n = 0, u = 0;
    size_t i;
    for (i = 0; str[i]; i++) {
        const int c = (int)(unsigned char)str[i];
        switch (k) {
        case 0:
            if (c >= 0x80) {
                if ((c & 0xe0) == 0xc0) {
                    u = c & 0x1f;
                    n = k = 1;
                }
                else if ((c & 0xf0) == 0xe0) {
                    u = c & 0x0f;
                    n = k = 2;
                }
                else if ((c & 0xf8) == 0xf0) {
                    u = c & 0x07;
                    n = k = 3;
                }
                else {
                    return FALSE;
                }
            }
            break;
        case 1:
        case 2:
        case 3:
            if ((c & 0xc0) == 0x80) {
                u <<= 6;
                u |= c & 0x3f;
                k--;
                if (k == 0) {
                    switch (n) {
                    case 1:
                        if (u < 0x80) return FALSE;
                        break;
                    case 2:
                        if (u < 0x800) return FALSE;
                        break;
                    case 3:
                        if (u < 0x10000 || u > 0x10ffff) return FALSE;
                        break;
                    default:
                        assert(((void)"unexpected control flow", 0));
                        return FALSE; /* never reached */
                    }
                    u = 0;
                    n = 0;
                }
            }
            else {
                return FALSE;
            }
            break;
        default:
            assert(((void)"unexpected control flow", 0));
            return FALSE; /* never reached */
        }
    }
    return (k == 0) ? TRUE : FALSE;
}

static size_t utf8_to_utf32(const char *seq, int *out) { /* without checking UTF-8 validity */
    const int c = (int)(unsigned char)seq[0];
    const size_t n =
        (c == 0) ? 0 : (c < 0x80) ? 1 :
        ((c & 0xe0) == 0xc0) ? 2 :
        ((c & 0xf0) == 0xe0) ? 3 :
        ((c & 0xf8) == 0xf0) ? 4 : 1;
    int u = 0;
    switch (n) {
    case 0:
    case 1:
        u = c;
        break;
    case 2:
        u = ((c & 0x1f) << 6) |
            ((int)(unsigned char)seq[1] & 0x3f);
        break;
    case 3:
        u = ((c & 0x0f) << 12) |
            (((int)(unsigned char)seq[1] & 0x3f) << 6) |
            (seq[1] ? ((int)(unsigned char)seq[2] & 0x3f) : 0);
        break;
    default:
        u = ((c & 0x07) << 18) |
            (((int)(unsigned char)seq[1] & 0x3f) << 12) |
            (seq[1] ? (((int)(unsigned char)seq[2] & 0x3f) << 6) : 0) |
            (seq[2] ? ((int)(unsigned char)seq[3] & 0x3f) : 0);
    }
    if (out) *out = u;
    return n;
}

static bool_t unescape_string(char *str, bool_t cls) { /* cls: TRUE if used for character class matching */
    bool_t b = TRUE;
    size_t i, j;
    for (j = 0, i = 0; str[i]; i++) {
        if (str[i] == '\\') {
            i++;
            switch (str[i]) {
            case '\0': str[j++] = '\\'; str[j] = '\0'; return FALSE;
            case '\'': str[j++] = '\''; break;
            case '\"': str[j++] = '\"'; break;
            case '0': str[j++] = '\x00'; break;
            case 'a': str[j++] = '\x07'; break;
            case 'b': str[j++] = '\x08'; break;
            case 'f': str[j++] = '\x0c'; break;
            case 'n': str[j++] = '\x0a'; break;
            case 'r': str[j++] = '\x0d'; break;
            case 't': str[j++] = '\x09'; break;
            case 'v': str[j++] = '\x0b'; break;
            case 'x':
                {
                    char s = 0, c;
                    size_t k;
                    for (k = 0; k < 2; k++) {
                        char d;
                        c = str[i + k + 1];
                        d = (c >= '0' && c <= '9') ? c - '0' :
                            (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                            (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                        if (d < 0) break;
                        s = (s << 4) | d;
                    }
                    if (k < 2) {
                        const size_t l = i + k;
                        str[j++] = '\\'; str[j++] = 'x';
                        while (i <= l) str[j++] = str[++i];
                        if (c == '\0') return FALSE;
                        b = FALSE;
                        continue;
                    }
                    str[j++] = s;
                    i += 2;
                }
                break;
            case 'u':
                {
                    int s = 0, t = 0;
                    char c;
                    size_t k;
                    for (k = 0; k < 4; k++) {
                        char d;
                        c = str[i + k + 1];
                        d = (c >= '0' && c <= '9') ? c - '0' :
                            (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                            (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                        if (d < 0) break;
                        s = (s << 4) | d;
                    }
                    if (k < 4 || (s & 0xfc00) == 0xdc00) { /* invalid character or invalid surrogate code point */
                        const size_t l = i + k;
                        str[j++] = '\\'; str[j++] = 'u';
                        while (i <= l) str[j++] = str[++i];
                        if (c == '\0') return FALSE;
                        b = FALSE;
                        continue;
                    }
                    if ((s & 0xfc00) == 0xd800) { /* surrogate pair */
                        for (k = 4; k < 10; k++) {
                            c = str[i + k + 1];
                            if (k == 4) {
                                if (c != '\\') break;
                            }
                            else if (k == 5) {
                                if (c != 'u') break;
                            }
                            else {
                                const char d =
                                    (c >= '0' && c <= '9') ? c - '0' :
                                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                                if (d < 0) break;
                                t = (t << 4) | d;
                            }
                        }
                        if (k < 10 || (t & 0xfc00) != 0xdc00) { /* invalid character or invalid surrogate code point */
                            const size_t l = i + 4; /* NOTE: Not i + k to redo with recovery. */
                            str[j++] = '\\'; str[j++] = 'u';
                            while (i <= l) str[j++] = str[++i];
                            b = FALSE;
                            continue;
                        }
                    }
                    {
                        const int u = t ? ((((s & 0x03ff) + 0x0040) << 10) | (t & 0x03ff)) : s;
                        if (u < 0x0080) {
                            str[j++] = (char)u;
                        }
                        else if (u < 0x0800) {
                            str[j++] = (char)(0xc0 | (u >> 6));
                            str[j++] = (char)(0x80 | (u & 0x3f));
                        }
                        else if (u < 0x010000) {
                            str[j++] = (char)(0xe0 | (u >> 12));
                            str[j++] = (char)(0x80 | ((u >> 6) & 0x3f));
                            str[j++] = (char)(0x80 | (u & 0x3f));
                        }
                        else if (u < 0x110000) {
                            str[j++] = (char)(0xf0 | (u >> 18));
                            str[j++] = (char)(0x80 | ((u >> 12) & 0x3f));
                            str[j++] = (char)(0x80 | ((u >>  6) & 0x3f));
                            str[j++] = (char)(0x80 | (u & 0x3f));
                        }
                        else { /* never reached theoretically; in case */
                            const size_t l = i + 10;
                            str[j++] = '\\'; str[j++] = 'u';
                            while (i <= l) str[j++] = str[++i];
                            b = FALSE;
                            continue;
                        }
                    }
                    i += t ? 10 : 4;
                }
                break;
            case '\n': break;
            case '\r': if (str[i + 1] == '\n') i++; break;
            case '\\':
                if (cls) str[j++] = '\\'; /* left for character class matching (ex. considering [\^\]\\]) */
                str[j++] = '\\';
                break;
            default: str[j++] = '\\'; str[j++] = str[i];
            }
        }
        else {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
    return b;
}

static const char *escape_character(char ch, char (*buf)[5]) {
    switch (ch) {
    case '\x00': strncpy(*buf, "\\0", 5); break;
    case '\x07': strncpy(*buf, "\\a", 5); break;
    case '\x08': strncpy(*buf, "\\b", 5); break;
    case '\x0c': strncpy(*buf, "\\f", 5); break;
    case '\x0a': strncpy(*buf, "\\n", 5); break;
    case '\x0d': strncpy(*buf, "\\r", 5); break;
    case '\x09': strncpy(*buf, "\\t", 5); break;
    case '\x0b': strncpy(*buf, "\\v", 5); break;
    case '\\':  strncpy(*buf, "\\\\", 5); break;
    case '\'':  strncpy(*buf, "\\\'", 5); break;
    case '\"':  strncpy(*buf, "\\\"", 5); break;
    default:
        if (ch >= '\x20' && ch < '\x7f')
            snprintf(*buf, 5, "%c", ch);
        else
            snprintf(*buf, 5, "\\x%02x", (int)(unsigned char)ch);
    }
    (*buf)[4] = '\0';
    return *buf;
}

static void remove_leading_blanks(char *str) {
    size_t i, j;
    for (i = 0; str[i]; i++) {
        if (
            str[i] != ' '  &&
            str[i] != '\v' &&
            str[i] != '\f' &&
            str[i] != '\t' &&
            str[i] != '\n' &&
            str[i] != '\r'
        ) break;
    }
    for (j = 0; str[i]; i++) {
        str[j++] = str[i];
    }
    str[j] = '\0';
}

static void remove_trailing_blanks(char *str) {
    size_t i, j;
    for (j = 0, i = 0; str[i]; i++) {
        if (
            str[i] != ' '  &&
            str[i] != '\v' &&
            str[i] != '\f' &&
            str[i] != '\t' &&
            str[i] != '\n' &&
            str[i] != '\r'
        ) j = i + 1;
    }
    str[j] = '\0';
}

static size_t find_trailing_blanks(const char *str) {
    size_t i, j;
    for (j = 0, i = 0; str[i]; i++) {
        if (
            str[i] != ' '  &&
            str[i] != '\v' &&
            str[i] != '\f' &&
            str[i] != '\t' &&
            str[i] != '\n' &&
            str[i] != '\r'
        ) j = i + 1;
    }
    return j;
}

static size_t count_characters(const char *str, size_t start, size_t end) {
    /* UTF-8 multibyte character support but without checking UTF-8 validity */
    size_t n = 0, i = start;
    while (i < end) {
        const int c = (int)(unsigned char)str[i];
        if (c == 0) break;
        n++;
        i += (c < 0x80) ? 1 : ((c & 0xe0) == 0xc0) ? 2 : ((c & 0xf0) == 0xe0) ? 3 : ((c & 0xf8) == 0xf0) ? 4 : /* invalid code */ 1;
    }
    return n;
}

static void make_header_identifier(char *str) {
    size_t i;
    for (i = 0; str[i]; i++) {
        str[i] =
            ((str[i] >= 'A' && str[i] <= 'Z') || (str[i] >= '0' && str[i] <= '9')) ? str[i] :
            (str[i] >= 'a' && str[i] <= 'z') ? str[i] - 'a' + 'A' : '_';
    }
}

static void file_pos__init(file_pos_t *pos) {
    pos->path = NULL;
    pos->line = VOID_VALUE;
    pos->col = VOID_VALUE;
}

static void file_pos__set(file_pos_t *pos, const char *path, size_t line, size_t col) {
    free(pos->path);
    pos->path = path ? strdup_e(path) : NULL;
    pos->line = line;
    pos->col = col;
}

static void file_pos__term(file_pos_t *pos) {
    free(pos->path);
}

static void file_id__get(FILE *file, const char *path, file_id_t *id) {
#ifdef _WIN32 /* Windows including MSVC and MinGW */
    if (GetFileInformationByHandle((HANDLE)_get_osfhandle(_fileno(file)), id) == 0) {
        print_error("Cannot get file information: %s\n", path);
        exit(2);
    }
#else
    if (fstat(fileno(file), id) != 0) {
        print_error("Cannot get file information: %s\n", path);
        exit(2);
    }
#endif
}

static bool_t file_id__equals(const file_id_t *id0, const file_id_t *id1) {
#ifdef _WIN32 /* Windows including MSVC and MinGW */
    return (
        id0->dwVolumeSerialNumber == id1->dwVolumeSerialNumber &&
        id0->nFileIndexHigh == id1->nFileIndexHigh &&
        id0->nFileIndexLow == id1->nFileIndexLow
    ) ? TRUE : FALSE;
#else
    return (id0->st_dev == id1->st_dev && id0->st_ino == id1->st_ino) ? TRUE : FALSE;
#endif
}

static stream_t stream__wrap(FILE *file, const char *path, size_t line) {
    stream_t s;
    s.file = file;
    s.path = path;
    s.line = line;
    return s;
}

static int stream__putc(stream_t *stream, int c) {
    const int r = fputc(c, stream->file);
    if (r == EOF) {
        print_error("File write error: %s\n", stream->path);
        exit(2);
    }
    if (stream->line != VOID_VALUE) {
        if (c == '\n') stream->line++;
    }
    return r;
}

static int stream__puts(stream_t *stream, const char *s) {
    const int r = fputs(s, stream->file);
    if (r == EOF) {
        print_error("File write error: %s\n", stream->path);
        exit(2);
    }
    if (stream->line != VOID_VALUE) {
        size_t i = 0;
        for (i = 0; s[i]; i++) {
            if (s[i] == '\n') stream->line++;
        }
    }
    return r;
}

__attribute__((format(printf, 2, 3)))
static int stream__printf(stream_t *stream, const char *format, ...) {
    if (stream->line != VOID_VALUE) {
#define M 1024
        char s[M], *p = NULL;
        int n = 0;
        size_t l = 0;
        {
            va_list a;
            va_start(a, format);
            n = vsnprintf(NULL, 0, format, a);
            va_end(a);
            if (n < 0) {
                print_error("Internal error [%d]\n", __LINE__);
                exit(2);
            }
            l = (size_t)n + 1;
        }
        p = (l > M) ? (char *)malloc_e(l) : s;
        {
            va_list a;
            va_start(a, format);
            n = vsnprintf(p, l, format, a);
            va_end(a);
            if (n < 0 || (size_t)n >= l) {
                print_error("Internal error [%d]\n", __LINE__);
                exit(2);
            }
        }
        stream__puts(stream, p);
        if (p != s) free(p);
        return n;
#undef M
    }
    else {
        int n;
        va_list a;
        va_start(a, format);
        n = vfprintf(stream->file, format, a);
        va_end(a);
        if (n < 0) {
            print_error("File write error: %s\n", stream->path);
            exit(2);
        }
        return n;
    }
}

static void stream__write_characters(stream_t *stream, char ch, size_t len) {
    size_t i;
    if (len == VOID_VALUE) return; /* for safety */
    for (i = 0; i < len; i++) stream__putc(stream, ch);
}

static void stream__write_text(stream_t *stream, const char *ptr, size_t len) {
    size_t i;
    if (len == VOID_VALUE) return; /* for safety */
    for (i = 0; i < len; i++) {
        if (ptr[i] == '\r') {
            if (i + 1 < len && ptr[i + 1] == '\n') i++;
            stream__putc(stream, '\n');
        }
        else {
            stream__putc(stream, ptr[i]);
        }
    }
}

static void stream__write_escaped_string(stream_t *stream, const char *ptr, size_t len) {
    char s[5];
    size_t i;
    if (len == VOID_VALUE) return; /* for safety */
    for (i = 0; i < len; i++) {
        stream__puts(stream, escape_character(ptr[i], &s));
    }
}

static void stream__write_line_directive(stream_t *stream, const char *path, size_t lineno) {
    stream__printf(stream, "#line " FMT_LU " \"", (ulong_t)(lineno + 1));
    stream__write_escaped_string(stream, path, strlen(path));
    stream__puts(stream, "\"\n");
}

static void stream__write_code_block(stream_t *stream, const char *ptr, size_t len, size_t indent, const char *path, size_t lineno) {
    bool_t b = FALSE;
    size_t i, j, k;
    if (len == VOID_VALUE) return; /* for safety */
    j = find_first_trailing_space(ptr, 0, len, &k);
    for (i = 0; i < j; i++) {
        if (
            ptr[i] != ' '  &&
            ptr[i] != '\v' &&
            ptr[i] != '\f' &&
            ptr[i] != '\t'
        ) break;
    }
    if (i < j) {
        if (stream->line != VOID_VALUE)
            stream__write_line_directive(stream, path, lineno);
        if (ptr[i] != '#')
            stream__write_characters(stream, ' ', indent);
        stream__write_text(stream, ptr + i, j - i);
        stream__putc(stream, '\n');
        b = TRUE;
    }
    else {
        lineno++;
    }
    if (k < len) {
        size_t m = VOID_VALUE;
        size_t h;
        for (i = k; i < len; i = h) {
            j = find_first_trailing_space(ptr, i, len, &h);
            if (i < j) {
                if (stream->line != VOID_VALUE && !b)
                    stream__write_line_directive(stream, path, lineno);
                if (ptr[i] != '#') {
                    const size_t l = count_indent_spaces(ptr, i, j, NULL);
                    if (m == VOID_VALUE || m > l) m = l;
                }
                b = TRUE;
            }
            else {
                if (!b) {
                    k = h;
                    lineno++;
                }
            }
        }
        for (i = k; i < len; i = h) {
            j = find_first_trailing_space(ptr, i, len, &h);
            if (i < j) {
                const size_t l = count_indent_spaces(ptr, i, j, &i);
                if (ptr[i] != '#') {
                    assert(m != VOID_VALUE); /* m must have a valid value */
                    assert(l >= m);
                    stream__write_characters(stream, ' ', l - m + indent);
                }
                stream__write_text(stream, ptr + i, j - i);
                stream__putc(stream, '\n');
                b = TRUE;
            }
            else if (h < len) {
                stream__putc(stream, '\n');
            }
        }
    }
    if (stream->line != VOID_VALUE && b)
        stream__write_line_directive(stream, stream->path, stream->line);
}

static void stream__write_footer(stream_t *stream, const char *ptr, size_t len, const char *path, size_t lineno) {
    bool_t b = FALSE;
    size_t i, j, k;
    if (len == VOID_VALUE) return; /* for safety */
    j = find_first_trailing_space(ptr, 0, len, &k);
    for (i = 0; i < j; i++) {
        if (
            ptr[i] != ' '  &&
            ptr[i] != '\v' &&
            ptr[i] != '\f' &&
            ptr[i] != '\t'
        ) break;
    }
    if (i < j) {
        if (stream->line != VOID_VALUE)
            stream__write_line_directive(stream, path, lineno);
        stream__write_text(stream, ptr + i, j - i);
        stream__putc(stream, '\n');
        b = TRUE;
    }
    else {
        lineno++;
    }
    if (k < len) {
        size_t h;
        for (i = k; i < len; i = h) {
            j = find_first_trailing_space(ptr, i, len, &h);
            if (i < j) {
                if (stream->line != VOID_VALUE && !b)
                    stream__write_line_directive(stream, path, lineno);
                b = TRUE;
                break;
            }
            else {
                if (!b) {
                    k = h;
                    lineno++;
                }
            }
        }
        for (i = k; i < len; i = h) {
            j = find_first_trailing_space(ptr, i, len, &h);
            if (i < j) {
                stream__write_text(stream, ptr + i, j - i);
                stream__putc(stream, '\n');
            }
            else if (h < len) {
                stream__putc(stream, '\n');
            }
        }
    }
}

static char *get_home_directory(void) {
#ifdef _MSC_VER
    char s[MAX_PATH];
    return (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, SHGFP_TYPE_DEFAULT, s) == S_OK) ? strdup_e(s) : NULL;
#else
    const char *const s = getenv("HOME");
    return (s && s[0]) ? strdup_e(s) : NULL;
#endif
}

#ifdef _MSC_VER

static char *get_appdata_directory(void) {
    char s[MAX_PATH];
    return (SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_DEFAULT, s) == S_OK) ? strdup_e(s) : NULL;
}

#endif /* _MSC_VER */

static bool_t is_absolute_path(const char *path) {
#ifdef _WIN32
    return (
        path[0] == '\\' ||
        (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':')
    ) ? TRUE : FALSE;
#else
    return (path[0] == '/') ? TRUE : FALSE;
#endif
}

static const char *extract_filename(const char *path) {
    size_t i = strlen(path);
    while (i > 0) {
        i--;
#ifdef _WIN32
        if (strchr("/\\:", path[i])) return path + i + 1;
#else
        if (path[i] == '/') return path + i + 1;
#endif
    }
    return path;
}

static char *replace_filename(const char *path, const char *name) {
    const char *const p = extract_filename(path);
    const size_t m = p - path;
    const size_t n = strlen(name);
    char *const s = (char *)malloc_e(m + n + 1);
    memcpy(s, path, m);
    memcpy(s + m, name, n + 1);
    return s;
}

static char *add_filename(const char *path, const char *name) {
    const size_t m = strlen(path);
    const size_t n = strlen(name);
#ifdef _WIN32
    const size_t d = (m > 0 && strchr("/\\:", path[m - 1]) == NULL) ? 1 : 0;
#else
    const size_t d = (m > 0 && path[m - 1] != '/') ? 1 : 0;
#endif
    char *const s = (char *)malloc_e(m + d + n + 1);
    memcpy(s, path, m);
    if (d) s[m] = '/';
    memcpy(s + m + d, name, n + 1);
    return s;
}

static const char *extract_fileext(const char *path) {
    const size_t n = strlen(path);
    size_t i = n;
    while (i > 0) {
        i--;
#ifdef _WIN32
        if (strchr("/\\:", path[i])) break;
#else
        if (path[i] == '/') break;
#endif
        if (path[i] == '.') return path + i;
    }
    return path + n;
}

static char *replace_fileext(const char *path, const char *ext) {
    const char *const p = extract_fileext(path);
    const size_t m = p - path;
    const size_t n = strlen(ext);
    char *const s = (char *)malloc_e(m + n + 2);
    memcpy(s, path, m);
    s[m] = '.';
    memcpy(s + m + 1, ext, n + 1);
    return s;
}

static char *add_fileext(const char *path, const char *ext) {
    const size_t m = strlen(path);
    const size_t n = strlen(ext);
    char *const s = (char *)malloc_e(m + n + 2);
    memcpy(s, path, m);
    s[m] = '.';
    memcpy(s + m + 1, ext, n + 1);
    return s;
}

static size_t hash_string(const char *str) {
    size_t i, h = 0;
    for (i = 0; str[i]; i++) {
        h = h * 31 + str[i];
    }
    return h;
}

static size_t populate_bits(size_t x) {
    x |= x >>  1;
    x |= x >>  2;
    x |= x >>  4;
    x |= x >>  8;
    x |= x >> 16;
#if (defined __SIZEOF_SIZE_T__ && __SIZEOF_SIZE_T__ == 8) /* gcc or clang */ || defined _WIN64 /* MSVC */
    x |= x >> 32;
#endif
    return x;
}

static size_t column_number(const input_state_t *input) { /* 0-based */
    assert(input->bufpos + input->bufcur >= input->linepos);
    if (input->ascii)
        return input->charnum + input->bufcur - ((input->linepos > input->bufpos) ? input->linepos - input->bufpos : 0);
    else
        return input->charnum + count_characters(
            input->buffer.buf, (input->linepos > input->bufpos) ? input->linepos - input->bufpos : 0, input->bufcur
        );
}

static void file_id_array__init(file_id_array_t *array) {
    array->len = 0;
    array->max = 0;
    array->buf = NULL;
}

static bool_t file_id_array__add_if_not_yet(file_id_array_t *array, const file_id_t *id) {
    size_t i;
    for (i = 0; i < array->len; i++) {
        if (file_id__equals(id, &(array->buf[i]))) return FALSE; /* already added */
    }
    if (array->max <= array->len) {
        const size_t n = array->len + 1;
        size_t m = array->max;
        if (m == 0) m = BUFFER_MIN_SIZE;
        while (m < n && m != 0) m <<= 1;
        if (m == 0) m = n; /* in case of shift overflow */
        array->buf = (file_id_t *)realloc_e(array->buf, sizeof(file_id_t) * m);
        array->max = m;
    }
    array->buf[array->len++] = *id;
    return TRUE; /* newly added */
}

static void file_id_array__term(file_id_array_t *array) {
    free(array->buf);
}

static void char_array__init(char_array_t *array) {
    array->len = 0;
    array->max = 0;
    array->buf = NULL;
}

static void char_array__add(char_array_t *array, char ch) {
    if (array->max <= array->len) {
        const size_t n = array->len + 1;
        size_t m = array->max;
        if (m == 0) m = BUFFER_MIN_SIZE;
        while (m < n && m != 0) m <<= 1;
        if (m == 0) m = n; /* in case of shift overflow */
        array->buf = (char *)realloc_e(array->buf, m);
        array->max = m;
    }
    array->buf[array->len++] = ch;
}

static void char_array__term(char_array_t *array) {
    free(array->buf);
}

static void string_array__init(string_array_t *array) {
    array->len = 0;
    array->max = 0;
    array->buf = NULL;
}

static void string_array__add(string_array_t *array, const char *str, size_t len) {
    if (array->max <= array->len) {
        const size_t n = array->len + 1;
        size_t m = array->max;
        if (m == 0) m = BUFFER_MIN_SIZE;
        while (m < n && m != 0) m <<= 1;
        if (m == 0) m = n; /* in case of shift overflow */
        array->buf = (char **)realloc_e(array->buf, sizeof(char *) * m);
        array->max = m;
    }
    array->buf[array->len++] = (len == VOID_VALUE) ? strdup_e(str) : strndup_e(str, len);
}

static void string_array__term(string_array_t *array) {
    size_t i;
    for (i = 0; i < array->len; i++) free(array->buf[i]);
    free(array->buf);
}

static void code_block__init(code_block_t *code) {
    code->text = NULL;
    code->len = 0;
    file_pos__init(&code->fpos);
}

static void code_block__term(code_block_t *code) {
    file_pos__term(&code->fpos);
    free(code->text);
}

static void code_block_array__init(code_block_array_t *array) {
    array->len = 0;
    array->max = 0;
    array->buf = NULL;
}

static code_block_t *code_block_array__create_entry(code_block_array_t *array) {
    if (array->max <= array->len) {
        const size_t n = array->len + 1;
        size_t m = array->max;
        if (m == 0) m = ARRAY_MIN_SIZE;
        while (m < n && m != 0) m <<= 1;
        if (m == 0) m = n; /* in case of shift overflow */
        array->buf = (code_block_t *)realloc_e(array->buf, sizeof(code_block_t) * m);
        array->max = m;
    }
    code_block__init(&array->buf[array->len]);
    return &array->buf[array->len++];
}

static void code_block_array__term(code_block_array_t *array) {
    while (array->len > 0) {
        array->len--;
        code_block__term(&array->buf[array->len]);
    }
    free(array->buf);
}

static void node_array__init(node_array_t *array) {
    array->len = 0;
    array->max = 0;
    array->buf = NULL;
}

static void node_array__add(node_array_t *array, node_t *node) {
    if (array->max <= array->len) {
        const size_t n = array->len + 1;
        size_t m = array->max;
        if (m == 0) m = ARRAY_MIN_SIZE;
        while (m < n && m != 0) m <<= 1;
        if (m == 0) m = n; /* in case of shift overflow */
        array->buf = (node_t **)realloc_e(array->buf, sizeof(node_t *) * m);
        array->max = m;
    }
    array->buf[array->len++] = node;
}

static void destroy_node(node_t *node);

static void node_array__term(node_array_t *array) {
    while (array->len > 0) {
        array->len--;
        destroy_node(array->buf[array->len]);
    }
    free(array->buf);
}

static void node_const_array__init(node_const_array_t *array) {
    array->len = 0;
    array->max = 0;
    array->buf = NULL;
}

static void node_const_array__add(node_const_array_t *array, const node_t *node) {
    if (array->max <= array->len) {
        const size_t n = array->len + 1;
        size_t m = array->max;
        if (m == 0) m = ARRAY_MIN_SIZE;
        while (m < n && m != 0) m <<= 1;
        if (m == 0) m = n; /* in case of shift overflow */
        array->buf = (const node_t **)realloc_e((node_t **)array->buf, sizeof(const node_t *) * m);
        array->max = m;
    }
    array->buf[array->len++] = node;
}

static void node_const_array__clear(node_const_array_t *array) {
    array->len = 0;
}

static void node_const_array__copy(node_const_array_t *array, const node_const_array_t *src) {
    size_t i;
    node_const_array__clear(array);
    for (i = 0; i < src->len; i++) {
        node_const_array__add(array, src->buf[i]);
    }
}

static void node_const_array__term(node_const_array_t *array) {
    free((node_t **)array->buf);
}

static input_state_t *create_input_state(const char *path, FILE *file, input_state_t *parent, const options_t *opts) {
    input_state_t *const input = (input_state_t *)malloc_e(sizeof(input_state_t));
    input->path = strdup_e((path && path[0]) ? path : "<stdin>");
    input->file = file ? file : (path && path[0]) ? fopen_rb_e(path) : stdin;
    input->ascii = opts->ascii;
    input->flags = CODE_FLAG__NONE;
    input->errnum = 0;
    input->linenum = 0;
    input->charnum = 0;
    input->linepos = 0;
    input->bufpos = 0;
    input->bufcur = 0;
    char_array__init(&input->buffer);
    input->parent = parent;
    return input;
}

static input_state_t *destroy_input_state(input_state_t *input) {
    input_state_t *parent;
    if (input == NULL) return NULL;
    parent = input->parent;
    char_array__term(&input->buffer);
    fclose_e(input->file, input->path);
    free(input->path);
    free(input);
    return parent;
}

static bool_t is_in_imported_input(const input_state_t *input) {
    return input->parent ? TRUE : FALSE;
}

static context_t *create_context(const char *ipath, const char *opath, const string_array_t *dirs, const options_t *opts) {
    context_t *const ctx = (context_t *)malloc_e(sizeof(context_t));
    ctx->spath = (opath && opath[0]) ? add_fileext(opath, "c") : replace_fileext((ipath && ipath[0]) ? ipath : "-", "c");
    ctx->hpath = (opath && opath[0]) ? add_fileext(opath, "h") : replace_fileext((ipath && ipath[0]) ? ipath : "-", "h");
    ctx->hid = strdup_e(extract_filename(ctx->hpath)); make_header_identifier(ctx->hid);
    ctx->vtype = NULL;
    ctx->atype = NULL;
    ctx->prefix = NULL;
    ctx->dirs = dirs;
    ctx->opts = *opts;
    ctx->flags = CODE_FLAG__NONE;
    ctx->errnum = 0;
    ctx->input = create_input_state(ipath, NULL, NULL, opts);
    file_id_array__init(&ctx->done);
    node_array__init(&ctx->rules);
    ctx->rulehash.mod = 0;
    ctx->rulehash.max = 0;
    ctx->rulehash.buf = NULL;
    code_block_array__init(&ctx->esource);
    code_block_array__init(&ctx->eheader);
    code_block_array__init(&ctx->source);
    code_block_array__init(&ctx->header);
    code_block_array__init(&ctx->fsource);
    return ctx;
}

static void destroy_context(context_t *ctx) {
    if (ctx == NULL) return;
    code_block_array__term(&ctx->fsource);
    code_block_array__term(&ctx->header);
    code_block_array__term(&ctx->source);
    code_block_array__term(&ctx->eheader);
    code_block_array__term(&ctx->esource);
    free((node_t **)ctx->rulehash.buf);
    node_array__term(&ctx->rules);
    file_id_array__term(&ctx->done);
    while (ctx->input) ctx->input = destroy_input_state(ctx->input);
    free(ctx->prefix);
    free(ctx->atype);
    free(ctx->vtype);
    free(ctx->hid);
    free(ctx->hpath);
    free(ctx->spath);
    free(ctx);
}

static node_t *create_node(node_type_t type) {
    node_t *const node = (node_t *)malloc_e(sizeof(node_t));
    node->type = type;
    switch (node->type) {
    case NODE_RULE:
        node->data.rule.name = NULL;
        node->data.rule.expr = NULL;
        node->data.rule.ref = 0;
        node->data.rule.used = FALSE;
        node_const_array__init(&node->data.rule.vars);
        node_const_array__init(&node->data.rule.capts);
        node_const_array__init(&node->data.rule.codes);
        file_pos__init(&node->data.rule.fpos);
        break;
    case NODE_REFERENCE:
        node->data.reference.var = NULL;
        node->data.reference.index = VOID_VALUE;
        node->data.reference.name = NULL;
        node->data.reference.rule = NULL;
        file_pos__init(&node->data.reference.fpos);
        break;
    case NODE_STRING:
        node->data.string.value = NULL;
        break;
    case NODE_CHARCLASS:
        node->data.charclass.value = NULL;
        break;
    case NODE_QUANTITY:
        node->data.quantity.min = node->data.quantity.max = 0;
        node->data.quantity.expr = NULL;
        break;
    case NODE_PREDICATE:
        node->data.predicate.neg = FALSE;
        node->data.predicate.expr = NULL;
        break;
    case NODE_SEQUENCE:
        node_array__init(&node->data.sequence.nodes);
        break;
    case NODE_ALTERNATE:
        node_array__init(&node->data.alternate.nodes);
        break;
    case NODE_CAPTURE:
        node->data.capture.expr = NULL;
        node->data.capture.index = VOID_VALUE;
        break;
    case NODE_EXPAND:
        node->data.expand.index = VOID_VALUE;
        file_pos__init(&node->data.expand.fpos);
        break;
    case NODE_ACTION:
        code_block__init(&node->data.action.code);
        node->data.action.index = VOID_VALUE;
        node_const_array__init(&node->data.action.vars);
        node_const_array__init(&node->data.action.capts);
        break;
    case NODE_ERROR:
        node->data.error.expr = NULL;
        code_block__init(&node->data.error.code);
        node->data.error.index = VOID_VALUE;
        node_const_array__init(&node->data.error.vars);
        node_const_array__init(&node->data.error.capts);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    return node;
}

static void destroy_node(node_t *node) {
    if (node == NULL) return;
    switch (node->type) {
    case NODE_RULE:
        file_pos__term(&node->data.rule.fpos);
        node_const_array__term(&node->data.rule.codes);
        node_const_array__term(&node->data.rule.capts);
        node_const_array__term(&node->data.rule.vars);
        destroy_node(node->data.rule.expr);
        free(node->data.rule.name);
        break;
    case NODE_REFERENCE:
        file_pos__term(&node->data.reference.fpos);
        free(node->data.reference.name);
        free(node->data.reference.var);
        break;
    case NODE_STRING:
        free(node->data.string.value);
        break;
    case NODE_CHARCLASS:
        free(node->data.charclass.value);
        break;
    case NODE_QUANTITY:
        destroy_node(node->data.quantity.expr);
        break;
    case NODE_PREDICATE:
        destroy_node(node->data.predicate.expr);
        break;
    case NODE_SEQUENCE:
        node_array__term(&node->data.sequence.nodes);
        break;
    case NODE_ALTERNATE:
        node_array__term(&node->data.alternate.nodes);
        break;
    case NODE_CAPTURE:
        destroy_node(node->data.capture.expr);
        break;
    case NODE_EXPAND:
        file_pos__term(&node->data.expand.fpos);
        break;
    case NODE_ACTION:
        node_const_array__term(&node->data.action.capts);
        node_const_array__term(&node->data.action.vars);
        code_block__term(&node->data.action.code);
        break;
    case NODE_ERROR:
        node_const_array__term(&node->data.error.capts);
        node_const_array__term(&node->data.error.vars);
        code_block__term(&node->data.error.code);
        destroy_node(node->data.error.expr);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    free(node);
}

static void make_rulehash(context_t *ctx) {
    size_t i, j;
    ctx->rulehash.mod = populate_bits(ctx->rules.len * 4);
    ctx->rulehash.max = ctx->rulehash.mod + 1;
    ctx->rulehash.buf = (const node_t **)realloc_e((node_t **)ctx->rulehash.buf, sizeof(const node_t *) * ctx->rulehash.max);
    for (i = 0; i < ctx->rulehash.max; i++) {
        ctx->rulehash.buf[i] = NULL;
    }
    for (i = 0; i < ctx->rules.len; i++) {
        node_rule_t *const rule = &ctx->rules.buf[i]->data.rule;
        assert(ctx->rules.buf[i]->type == NODE_RULE);
        j = hash_string(rule->name) & ctx->rulehash.mod;
        while (ctx->rulehash.buf[j] != NULL) {
            if (strcmp(rule->name, ctx->rulehash.buf[j]->data.rule.name) == 0) {
                assert(rule->ref == 0);
                assert(ctx->rulehash.buf[j]->data.rule.ref <= 0); /* always 0 or -1 */
                rule->ref = -1; /* marks as duplicate */
                ((node_t *)ctx->rulehash.buf[j])->data.rule.ref = -1; /* marks as duplicate */
                goto EXCEPTION;
            }
            j = (j + 1) & ctx->rulehash.mod;
        }
        ctx->rulehash.buf[j] = ctx->rules.buf[i];

    EXCEPTION:;
    }
}

static const node_t *lookup_rulehash(const context_t *ctx, const char *name) {
    size_t j = hash_string(name) & ctx->rulehash.mod;
    while (ctx->rulehash.buf[j] != NULL && strcmp(name, ctx->rulehash.buf[j]->data.rule.name) != 0) {
        j = (j + 1) & ctx->rulehash.mod;
    }
    return (ctx->rulehash.buf[j] != NULL) ? ctx->rulehash.buf[j] : NULL;
}

static void link_references(context_t *ctx, node_t *node) {
    if (node == NULL) return;
    switch (node->type) {
    case NODE_RULE:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    case NODE_REFERENCE:
        node->data.reference.rule = lookup_rulehash(ctx, node->data.reference.name);
        if (node->data.reference.rule == NULL) {
            print_error(
                "%s:" FMT_LU ":" FMT_LU ": No definition of rule: '%s'\n",
                node->data.reference.fpos.path,
                (ulong_t)(node->data.reference.fpos.line + 1), (ulong_t)(node->data.reference.fpos.col + 1),
                node->data.reference.name
            );
            ctx->errnum++;
        }
        else if (node->data.reference.rule->data.rule.ref >= 0) { /* the target rule is not defined multiple times */
            assert(node->data.reference.rule->type == NODE_RULE);
            ((node_t *)node->data.reference.rule)->data.rule.ref++;
        }
        break;
    case NODE_STRING:
        break;
    case NODE_CHARCLASS:
        break;
    case NODE_QUANTITY:
        link_references(ctx, node->data.quantity.expr);
        break;
    case NODE_PREDICATE:
        link_references(ctx, node->data.predicate.expr);
        break;
    case NODE_SEQUENCE:
        {
            size_t i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                link_references(ctx, node->data.sequence.nodes.buf[i]);
            }
        }
        break;
    case NODE_ALTERNATE:
        {
            size_t i;
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                link_references(ctx, node->data.alternate.nodes.buf[i]);
            }
        }
        break;
    case NODE_CAPTURE:
        link_references(ctx, node->data.capture.expr);
        break;
    case NODE_EXPAND:
        break;
    case NODE_ACTION:
        break;
    case NODE_ERROR:
        link_references(ctx, node->data.error.expr);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
}

static void mark_rules_if_used(context_t *ctx, node_t *node) {
    if (node == NULL) return;
    switch (node->type) {
    case NODE_RULE:
        if (!node->data.rule.used) {
            node->data.rule.used = TRUE;
            mark_rules_if_used(ctx, node->data.rule.expr);
        }
        break;
    case NODE_REFERENCE:
        mark_rules_if_used(ctx, (node_t *)node->data.reference.rule);
        break;
    case NODE_STRING:
        break;
    case NODE_CHARCLASS:
        break;
    case NODE_QUANTITY:
        mark_rules_if_used(ctx, node->data.quantity.expr);
        break;
    case NODE_PREDICATE:
        mark_rules_if_used(ctx, node->data.predicate.expr);
        break;
    case NODE_SEQUENCE:
        {
            size_t i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                mark_rules_if_used(ctx, node->data.sequence.nodes.buf[i]);
            }
        }
        break;
    case NODE_ALTERNATE:
        {
            size_t i;
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                mark_rules_if_used(ctx, node->data.alternate.nodes.buf[i]);
            }
        }
        break;
    case NODE_CAPTURE:
        mark_rules_if_used(ctx, node->data.capture.expr);
        break;
    case NODE_EXPAND:
        break;
    case NODE_ACTION:
        break;
    case NODE_ERROR:
        mark_rules_if_used(ctx, node->data.error.expr);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
}

static void unreference_rules_from_unused_rule(context_t *ctx, node_t *node) {
    if (node == NULL) return;
    switch (node->type) {
    case NODE_RULE:
        unreference_rules_from_unused_rule(ctx, node->data.rule.expr);
        break;
    case NODE_REFERENCE:
        if (node->data.reference.rule && node->data.reference.rule->data.rule.ref > 0)
            ((node_t *)node->data.reference.rule)->data.rule.ref--;
        break;
    case NODE_STRING:
        break;
    case NODE_CHARCLASS:
        break;
    case NODE_QUANTITY:
        unreference_rules_from_unused_rule(ctx, node->data.quantity.expr);
        break;
    case NODE_PREDICATE:
        unreference_rules_from_unused_rule(ctx, node->data.predicate.expr);
        break;
    case NODE_SEQUENCE:
        {
            size_t i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                unreference_rules_from_unused_rule(ctx, node->data.sequence.nodes.buf[i]);
            }
        }
        break;
    case NODE_ALTERNATE:
        {
            size_t i;
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                unreference_rules_from_unused_rule(ctx, node->data.alternate.nodes.buf[i]);
            }
        }
        break;
    case NODE_CAPTURE:
        unreference_rules_from_unused_rule(ctx, node->data.capture.expr);
        break;
    case NODE_EXPAND:
        break;
    case NODE_ACTION:
        break;
    case NODE_ERROR:
        unreference_rules_from_unused_rule(ctx, node->data.error.expr);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
}

static void verify_variables(context_t *ctx, node_t *node, node_const_array_t *vars) {
    node_const_array_t a;
    const bool_t b = (vars == NULL) ? TRUE : FALSE;
    if (node == NULL) return;
    if (b) {
        node_const_array__init(&a);
        vars = &a;
    }
    switch (node->type) {
    case NODE_RULE:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    case NODE_REFERENCE:
        if (node->data.reference.index != VOID_VALUE) {
            size_t i;
            for (i = 0; i < vars->len; i++) {
                assert(vars->buf[i]->type == NODE_REFERENCE);
                if (node->data.reference.index == vars->buf[i]->data.reference.index) break;
            }
            if (i == vars->len) node_const_array__add(vars, node);
        }
        break;
    case NODE_STRING:
        break;
    case NODE_CHARCLASS:
        break;
    case NODE_QUANTITY:
        verify_variables(ctx, node->data.quantity.expr, vars);
        break;
    case NODE_PREDICATE:
        verify_variables(ctx, node->data.predicate.expr, vars);
        break;
    case NODE_SEQUENCE:
        {
            size_t i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                verify_variables(ctx, node->data.sequence.nodes.buf[i], vars);
            }
        }
        break;
    case NODE_ALTERNATE:
        {
            size_t i, j, k, m = vars->len;
            node_const_array_t v;
            node_const_array__init(&v);
            node_const_array__copy(&v, vars);
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                v.len = m;
                verify_variables(ctx, node->data.alternate.nodes.buf[i], &v);
                for (j = m; j < v.len; j++) {
                    for (k = m; k < vars->len; k++) {
                        if (v.buf[j]->data.reference.index == vars->buf[k]->data.reference.index) break;
                    }
                    if (k == vars->len) node_const_array__add(vars, v.buf[j]);
                }
            }
            node_const_array__term(&v);
        }
        break;
    case NODE_CAPTURE:
        verify_variables(ctx, node->data.capture.expr, vars);
        break;
    case NODE_EXPAND:
        break;
    case NODE_ACTION:
        node_const_array__copy(&node->data.action.vars, vars);
        break;
    case NODE_ERROR:
        node_const_array__copy(&node->data.error.vars, vars);
        verify_variables(ctx, node->data.error.expr, vars);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    if (b) {
        node_const_array__term(&a);
    }
}

static void verify_captures(context_t *ctx, node_t *node, node_const_array_t *capts) {
    node_const_array_t a;
    const bool_t b = (capts == NULL) ? TRUE : FALSE;
    if (node == NULL) return;
    if (b) {
        node_const_array__init(&a);
        capts = &a;
    }
    switch (node->type) {
    case NODE_RULE:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    case NODE_REFERENCE:
        break;
    case NODE_STRING:
        break;
    case NODE_CHARCLASS:
        break;
    case NODE_QUANTITY:
        verify_captures(ctx, node->data.quantity.expr, capts);
        break;
    case NODE_PREDICATE:
        verify_captures(ctx, node->data.predicate.expr, capts);
        break;
    case NODE_SEQUENCE:
        {
            size_t i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                verify_captures(ctx, node->data.sequence.nodes.buf[i], capts);
            }
        }
        break;
    case NODE_ALTERNATE:
        {
            size_t i, j, m = capts->len;
            node_const_array_t v;
            node_const_array__init(&v);
            node_const_array__copy(&v, capts);
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                v.len = m;
                verify_captures(ctx, node->data.alternate.nodes.buf[i], &v);
                for (j = m; j < v.len; j++) {
                    node_const_array__add(capts, v.buf[j]);
                }
            }
            node_const_array__term(&v);
        }
        break;
    case NODE_CAPTURE:
        verify_captures(ctx, node->data.capture.expr, capts);
        node_const_array__add(capts, node);
        break;
    case NODE_EXPAND:
        {
            size_t i;
            for (i = 0; i < capts->len; i++) {
                assert(capts->buf[i]->type == NODE_CAPTURE);
                if (node->data.expand.index == capts->buf[i]->data.capture.index) break;
            }
            if (i >= capts->len && node->data.expand.index != VOID_VALUE) {
                print_error(
                    "%s:" FMT_LU ":" FMT_LU ": Capture " FMT_LU " not available at this position\n",
                    node->data.expand.fpos.path,
                    (ulong_t)(node->data.expand.fpos.line + 1), (ulong_t)(node->data.expand.fpos.col + 1),
                    (ulong_t)(node->data.expand.index + 1)
                );
                ctx->errnum++;
            }
        }
        break;
    case NODE_ACTION:
        node_const_array__copy(&node->data.action.capts, capts);
        break;
    case NODE_ERROR:
        node_const_array__copy(&node->data.error.capts, capts);
        verify_captures(ctx, node->data.error.expr, capts);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    if (b) {
        node_const_array__term(&a);
    }
}

static void dump_escaped_string(const char *str) {
    char s[5];
    if (str == NULL) {
        fprintf(stdout, "null");
        return;
    }
    while (*str) {
        fprintf(stdout, "%s", escape_character(*str++, &s));
    }
}

static void dump_integer_value(size_t value) {
    if (value == VOID_VALUE) {
        fprintf(stdout, "void");
    }
    else {
        fprintf(stdout, FMT_LU, (ulong_t)value);
    }
}

static void dump_node(context_t *ctx, const node_t *node, const int indent) {
    if (node == NULL) return;
    switch (node->type) {
    case NODE_RULE:
        fprintf(
            stdout, "%*sRule(name:'%s', ref:%d, vars.len:" FMT_LU ", capts.len:" FMT_LU ", codes.len:" FMT_LU ") {\n",
            indent, "", node->data.rule.name, node->data.rule.ref,
            (ulong_t)node->data.rule.vars.len, (ulong_t)node->data.rule.capts.len, (ulong_t)node->data.rule.codes.len
        );
        dump_node(ctx, node->data.rule.expr, indent + 2);
        fprintf(stdout, "%*s}\n", indent, "");
        break;
    case NODE_REFERENCE:
        fprintf(stdout, "%*sReference(var:'%s', index:", indent, "", node->data.reference.var);
        dump_integer_value(node->data.reference.index);
        fprintf(
            stdout, ", name:'%s', rule:'%s')\n", node->data.reference.name,
            (node->data.reference.rule) ? node->data.reference.rule->data.rule.name : NULL
        );
        break;
    case NODE_STRING:
        fprintf(stdout, "%*sString(value:'", indent, "");
        dump_escaped_string(node->data.string.value);
        fprintf(stdout, "')\n");
        break;
    case NODE_CHARCLASS:
        fprintf(stdout, "%*sCharclass(value:'", indent, "");
        dump_escaped_string(node->data.charclass.value);
        fprintf(stdout, "')\n");
        break;
    case NODE_QUANTITY:
        fprintf(stdout, "%*sQuantity(min:%d, max:%d) {\n", indent, "", node->data.quantity.min, node->data.quantity.max);
        dump_node(ctx, node->data.quantity.expr, indent + 2);
        fprintf(stdout, "%*s}\n", indent, "");
        break;
    case NODE_PREDICATE:
        fprintf(stdout, "%*sPredicate(neg:%d) {\n", indent, "", node->data.predicate.neg);
        dump_node(ctx, node->data.predicate.expr, indent + 2);
        fprintf(stdout, "%*s}\n", indent, "");
        break;
    case NODE_SEQUENCE:
        fprintf(
            stdout, "%*sSequence(max:" FMT_LU ", len:" FMT_LU ") {\n",
            indent, "", (ulong_t)node->data.sequence.nodes.max, (ulong_t)node->data.sequence.nodes.len
        );
        {
            size_t i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                dump_node(ctx, node->data.sequence.nodes.buf[i], indent + 2);
            }
        }
        fprintf(stdout, "%*s}\n", indent, "");
        break;
    case NODE_ALTERNATE:
        fprintf(
            stdout, "%*sAlternate(max:" FMT_LU ", len:" FMT_LU ") {\n",
            indent, "", (ulong_t)node->data.alternate.nodes.max, (ulong_t)node->data.alternate.nodes.len
        );
        {
            size_t i;
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                dump_node(ctx, node->data.alternate.nodes.buf[i], indent + 2);
            }
        }
        fprintf(stdout, "%*s}\n", indent, "");
        break;
    case NODE_CAPTURE:
        fprintf(stdout, "%*sCapture(index:", indent, "");
        dump_integer_value(node->data.capture.index);
        fprintf(stdout, ") {\n");
        dump_node(ctx, node->data.capture.expr, indent + 2);
        fprintf(stdout, "%*s}\n", indent, "");
        break;
    case NODE_EXPAND:
        fprintf(stdout, "%*sExpand(index:", indent, "");
        dump_integer_value(node->data.expand.index);
        fprintf(stdout, ")\n");
        break;
    case NODE_ACTION:
        fprintf(stdout, "%*sAction(index:", indent, "");
        dump_integer_value(node->data.action.index);
        fprintf(stdout, ", code:{");
        dump_escaped_string(node->data.action.code.text);
        fprintf(stdout, "}, vars:");
        if (node->data.action.vars.len + node->data.action.capts.len > 0) {
            size_t i;
            fprintf(stdout, "\n");
            for (i = 0; i < node->data.action.vars.len; i++) {
                fprintf(stdout, "%*s'%s'\n", indent + 2, "", node->data.action.vars.buf[i]->data.reference.var);
            }
            for (i = 0; i < node->data.action.capts.len; i++) {
                fprintf(stdout, "%*s$" FMT_LU "\n", indent + 2, "", (ulong_t)(node->data.action.capts.buf[i]->data.capture.index + 1));
            }
            fprintf(stdout, "%*s)\n", indent, "");
        }
        else {
            fprintf(stdout, "none)\n");
        }
        break;
    case NODE_ERROR:
        fprintf(stdout, "%*sError(index:", indent, "");
        dump_integer_value(node->data.error.index);
        fprintf(stdout, ", code:{");
        dump_escaped_string(node->data.error.code.text);
        fprintf(stdout, "}, vars:\n");
        {
            size_t i;
            for (i = 0; i < node->data.error.vars.len; i++) {
                fprintf(stdout, "%*s'%s'\n", indent + 2, "", node->data.error.vars.buf[i]->data.reference.var);
            }
            for (i = 0; i < node->data.error.capts.len; i++) {
                fprintf(stdout, "%*s$" FMT_LU "\n", indent + 2, "", (ulong_t)(node->data.error.capts.buf[i]->data.capture.index + 1));
            }
        }
        fprintf(stdout, "%*s) {\n", indent, "");
        dump_node(ctx, node->data.error.expr, indent + 2);
        fprintf(stdout, "%*s}\n", indent, "");
        break;
    default:
        print_error("%*sInternal error [%d]\n", indent, "", __LINE__);
        exit(-1);
    }
}

static size_t refill_buffer(input_state_t *input, size_t num) {
    if (input->buffer.len >= input->bufcur + num) return input->buffer.len - input->bufcur;
    while (input->buffer.len < input->bufcur + num) {
        const int c = fgetc_e(input->file, input->path);
        if (c == EOF) break;
        char_array__add(&input->buffer, (char)c);
    }
    return input->buffer.len - input->bufcur;
}

static void commit_buffer(input_state_t *input) {
    assert(input->buffer.len >= input->bufcur);
    if (input->linepos < input->bufpos + input->bufcur)
        input->charnum += input->ascii ? input->bufcur : count_characters(input->buffer.buf, 0, input->bufcur);
    memmove(input->buffer.buf, input->buffer.buf + input->bufcur, input->buffer.len - input->bufcur);
    input->buffer.len -= input->bufcur;
    input->bufpos += input->bufcur;
    input->bufcur = 0;
}

static bool_t match_eof(input_state_t *input) {
    return (refill_buffer(input, 1) < 1) ? TRUE : FALSE;
}

static bool_t match_eol(input_state_t *input) {
    if (refill_buffer(input, 1) >= 1) {
        switch (input->buffer.buf[input->bufcur]) {
        case '\n':
            input->bufcur++;
            input->linenum++;
            input->charnum = 0;
            input->linepos = input->bufpos + input->bufcur;
            return TRUE;
        case '\r':
            input->bufcur++;
            if (refill_buffer(input, 1) >= 1) {
                if (input->buffer.buf[input->bufcur] == '\n') input->bufcur++;
            }
            input->linenum++;
            input->charnum = 0;
            input->linepos = input->bufpos + input->bufcur;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_character(input_state_t *input, char ch) {
    if (refill_buffer(input, 1) >= 1) {
        if (input->buffer.buf[input->bufcur] == ch) {
            input->bufcur++;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_character_range(input_state_t *input, char min, char max) {
    if (refill_buffer(input, 1) >= 1) {
        const char c = input->buffer.buf[input->bufcur];
        if (c >= min && c <= max) {
            input->bufcur++;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_character_set(input_state_t *input, const char *chs) {
    if (refill_buffer(input, 1) >= 1) {
        const char c = input->buffer.buf[input->bufcur];
        size_t i;
        for (i = 0; chs[i]; i++) {
            if (c == chs[i]) {
                input->bufcur++;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static bool_t match_character_any(input_state_t *input) {
    if (refill_buffer(input, 1) >= 1) {
        input->bufcur++;
        return TRUE;
    }
    return FALSE;
}

static bool_t match_string(input_state_t *input, const char *str) {
    const size_t n = strlen(str);
    if (refill_buffer(input, n) >= n) {
        if (strncmp(input->buffer.buf + input->bufcur, str, n) == 0) {
            input->bufcur += n;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_blank(input_state_t *input) {
    return match_character_set(input, " \t\v\f");
}

static bool_t match_section_line_(input_state_t *input, const char *head) {
    if (match_string(input, head)) {
        while (!match_eol(input) && !match_eof(input)) match_character_any(input);
        return TRUE;
    }
    return FALSE;
}

static bool_t match_section_line_continuable_(input_state_t *input, const char *head) {
    if (match_string(input, head)) {
        while (!match_eof(input)) {
            const size_t p = input->bufcur;
            if (match_eol(input)) {
                if (input->buffer.buf[p - 1] != '\\') break;
            }
            else {
                match_character_any(input);
            }
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_section_block_(input_state_t *input, const char *left, const char *right, const char *name) {
    const size_t l = input->linenum;
    const size_t m = column_number(input);
    if (match_string(input, left)) {
        while (!match_string(input, right)) {
            if (match_eof(input)) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Premature EOF in %s\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), name);
                input->errnum++;
                break;
            }
            if (!match_eol(input)) match_character_any(input);
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_quotation_(input_state_t *input, const char *left, const char *right, const char *name) {
    const size_t l = input->linenum;
    const size_t m = column_number(input);
    if (match_string(input, left)) {
        while (!match_string(input, right)) {
            if (match_eof(input)) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Premature EOF in %s\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), name);
                input->errnum++;
                break;
            }
            if (match_character(input, '\\')) {
                if (!match_eol(input)) match_character_any(input);
            }
            else {
                if (match_eol(input)) {
                    print_error("%s:" FMT_LU ":" FMT_LU ": Premature EOL in %s\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), name);
                    input->errnum++;
                    break;
                }
                match_character_any(input);
            }
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_directive_c(input_state_t *input) {
    return match_section_line_continuable_(input, "#");
}

static bool_t match_comment(input_state_t *input) {
    return match_section_line_(input, "#");
}

static bool_t match_comment_c(input_state_t *input) {
    return match_section_block_(input, "/*", "*/", "C comment");
}

static bool_t match_comment_cxx(input_state_t *input) {
    return match_section_line_(input, "//");
}

static bool_t match_quotation_single(input_state_t *input) {
    return match_quotation_(input, "\'", "\'", "single quotation");
}

static bool_t match_quotation_double(input_state_t *input) {
    return match_quotation_(input, "\"", "\"", "double quotation");
}

static bool_t match_character_class(input_state_t *input) {
    return match_quotation_(input, "[", "]", "character class");
}

static bool_t match_spaces(input_state_t *input) {
    size_t n = 0;
    while (match_blank(input) || match_eol(input) || match_comment(input)) n++;
    return (n > 0) ? TRUE : FALSE;
}

static bool_t match_number(input_state_t *input) {
    if (match_character_range(input, '0', '9')) {
        while (match_character_range(input, '0', '9'));
        return TRUE;
    }
    return FALSE;
}

static bool_t match_identifier(input_state_t *input) {
    if (
        match_character_range(input, 'a', 'z') ||
        match_character_range(input, 'A', 'Z') ||
        match_character(input, '_')
    ) {
        while (
            match_character_range(input, 'a', 'z') ||
            match_character_range(input, 'A', 'Z') ||
            match_character_range(input, '0', '9') ||
            match_character(input, '_')
        );
        return TRUE;
    }
    return FALSE;
}

static bool_t match_code_block(input_state_t *input) {
    const size_t l = input->linenum;
    const size_t m = column_number(input);
    if (match_character(input, '{')) {
        int d = 1;
        for (;;) {
            if (match_eof(input)) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Premature EOF in code block\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
                input->errnum++;
                break;
            }
            if (
                match_directive_c(input) ||
                match_comment_c(input) ||
                match_comment_cxx(input) ||
                match_quotation_single(input) ||
                match_quotation_double(input)
            ) continue;
            if (match_character(input, '{')) {
                d++;
            }
            else if (match_character(input, '}')) {
                d--;
                if (d == 0) break;
            }
            else {
                if (!match_eol(input)) {
                    if (match_character(input, '$')) {
                        input->buffer.buf[input->bufcur - 1] = '_';
                    }
                    else {
                        match_character_any(input);
                    }
                }
            }
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_footer_start(input_state_t *input) {
    return match_string(input, "%%");
}

static node_t *parse_expression(input_state_t *input, node_t *rule);

static node_t *parse_primary(input_state_t *input, node_t *rule) {
    const size_t p = input->bufcur;
    const size_t l = input->linenum;
    const size_t m = column_number(input);
    const size_t n = input->charnum;
    const size_t o = input->linepos;
    node_t *n_p = NULL;
    if (match_identifier(input)) {
        const size_t q = input->bufcur;
        size_t r = VOID_VALUE, s = VOID_VALUE;
        match_spaces(input);
        if (match_character(input, ':')) {
            match_spaces(input);
            r = input->bufcur;
            if (!match_identifier(input)) goto EXCEPTION;
            s = input->bufcur;
            match_spaces(input);
        }
        if (match_string(input, "<-")) goto EXCEPTION;
        n_p = create_node(NODE_REFERENCE);
        if (r == VOID_VALUE) {
            assert(q >= p);
            n_p->data.reference.var = NULL;
            n_p->data.reference.index = VOID_VALUE;
            n_p->data.reference.name = strndup_e(input->buffer.buf + p, q - p);
        }
        else {
            assert(s != VOID_VALUE); /* s should have a valid value when r has a valid value */
            assert(q >= p);
            n_p->data.reference.var = strndup_e(input->buffer.buf + p, q - p);
            if (n_p->data.reference.var[0] == '_') {
                print_error(
                    "%s:" FMT_LU ":" FMT_LU ": Leading underscore in variable name '%s'\n",
                    input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), n_p->data.reference.var
                );
                input->errnum++;
            }
            {
                size_t i;
                for (i = 0; i < rule->data.rule.vars.len; i++) {
                    assert(rule->data.rule.vars.buf[i]->type == NODE_REFERENCE);
                    if (strcmp(n_p->data.reference.var, rule->data.rule.vars.buf[i]->data.reference.var) == 0) break;
                }
                if (i == rule->data.rule.vars.len) node_const_array__add(&rule->data.rule.vars, n_p);
                n_p->data.reference.index = i;
            }
            assert(s >= r);
            n_p->data.reference.name = strndup_e(input->buffer.buf + r, s - r);
        }
        file_pos__set(&n_p->data.reference.fpos, input->path, l, m);
    }
    else if (match_character(input, '(')) {
        match_spaces(input);
        n_p = parse_expression(input, rule);
        if (n_p == NULL) goto EXCEPTION;
        if (!match_character(input, ')')) goto EXCEPTION;
        match_spaces(input);
    }
    else if (match_character(input, '<')) {
        match_spaces(input);
        n_p = create_node(NODE_CAPTURE);
        n_p->data.capture.index = rule->data.rule.capts.len;
        node_const_array__add(&rule->data.rule.capts, n_p);
        n_p->data.capture.expr = parse_expression(input, rule);
        if (n_p->data.capture.expr == NULL || !match_character(input, '>')) {
            rule->data.rule.capts.len = n_p->data.capture.index;
            goto EXCEPTION;
        }
        match_spaces(input);
    }
    else if (match_character(input, '$')) {
        size_t p;
        match_spaces(input);
        p = input->bufcur;
        if (match_number(input)) {
            const size_t q = input->bufcur;
            char *s;
            match_spaces(input);
            n_p = create_node(NODE_EXPAND);
            assert(q >= p);
            s = strndup_e(input->buffer.buf + p, q - p);
            n_p->data.expand.index = string_to_size_t(s);
            if (n_p->data.expand.index == VOID_VALUE) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Invalid unsigned number '%s'\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), s);
                input->errnum++;
            }
            else if (n_p->data.expand.index == 0) {
                print_error("%s:" FMT_LU ":" FMT_LU ": 0 not allowed\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
                input->errnum++;
            }
            else if (s[0] == '0') {
                print_error("%s:" FMT_LU ":" FMT_LU ": 0-prefixed number not allowed\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
                input->errnum++;
                n_p->data.expand.index = 0;
            }
            free(s);
            if (n_p->data.expand.index > 0 && n_p->data.expand.index != VOID_VALUE) {
                n_p->data.expand.index--;
                file_pos__set(&n_p->data.expand.fpos, input->path, l, m);
            }
        }
        else {
            goto EXCEPTION;
        }
    }
    else if (match_character(input, '.')) {
        match_spaces(input);
        n_p = create_node(NODE_CHARCLASS);
        n_p->data.charclass.value = NULL;
        if (!input->ascii) {
            input->flags |= CODE_FLAG__UTF8_CHARCLASS_USED;
        }
    }
    else if (match_character_class(input)) {
        const size_t q = input->bufcur;
        match_spaces(input);
        n_p = create_node(NODE_CHARCLASS);
        n_p->data.charclass.value = strndup_e(input->buffer.buf + p + 1, q - p - 2);
        if (!unescape_string(n_p->data.charclass.value, TRUE)) {
            print_error("%s:" FMT_LU ":" FMT_LU ": Illegal escape sequence\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
            input->errnum++;
        }
        if (!input->ascii && !is_valid_utf8_string(n_p->data.charclass.value)) {
            print_error("%s:" FMT_LU ":" FMT_LU ": Invalid UTF-8 string\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
            input->errnum++;
        }
        if (!input->ascii && n_p->data.charclass.value[0] != '\0') {
            input->flags |= CODE_FLAG__UTF8_CHARCLASS_USED;
        }
    }
    else if (match_quotation_single(input) || match_quotation_double(input)) {
        const size_t q = input->bufcur;
        match_spaces(input);
        n_p = create_node(NODE_STRING);
        n_p->data.string.value = strndup_e(input->buffer.buf + p + 1, q - p - 2);
        if (!unescape_string(n_p->data.string.value, FALSE)) {
            print_error("%s:" FMT_LU ":" FMT_LU ": Illegal escape sequence\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
            input->errnum++;
        }
        if (!input->ascii && !is_valid_utf8_string(n_p->data.string.value)) {
            print_error("%s:" FMT_LU ":" FMT_LU ": Invalid UTF-8 string\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
            input->errnum++;
        }
    }
    else if (match_code_block(input)) {
        const size_t q = input->bufcur;
        match_spaces(input);
        n_p = create_node(NODE_ACTION);
        n_p->data.action.code.text = strndup_e(input->buffer.buf + p + 1, q - p - 2);
        n_p->data.action.code.len = find_trailing_blanks(n_p->data.action.code.text);
        file_pos__set(&n_p->data.action.code.fpos, input->path, l, m);
        n_p->data.action.index = rule->data.rule.codes.len;
        node_const_array__add(&rule->data.rule.codes, n_p);
    }
    else {
        goto EXCEPTION;
    }
    return n_p;

EXCEPTION:;
    destroy_node(n_p);
    input->bufcur = p;
    input->linenum = l;
    input->charnum = n;
    input->linepos = o;
    return NULL;
}

static node_t *parse_term(input_state_t *input, node_t *rule) {
    const size_t p = input->bufcur;
    const size_t l = input->linenum;
    const size_t n = input->charnum;
    const size_t o = input->linepos;
    node_t *n_p = NULL;
    node_t *n_q = NULL;
    node_t *n_r = NULL;
    node_t *n_t = NULL;
    const char t = match_character(input, '&') ? '&' : match_character(input, '!') ? '!' : '\0';
    if (t) match_spaces(input);
    n_p = parse_primary(input, rule);
    if (n_p == NULL) goto EXCEPTION;
    if (match_character(input, '*')) {
        match_spaces(input);
        n_q = create_node(NODE_QUANTITY);
        n_q->data.quantity.min = 0;
        n_q->data.quantity.max = -1;
        n_q->data.quantity.expr = n_p;
    }
    else if (match_character(input, '+')) {
        match_spaces(input);
        n_q = create_node(NODE_QUANTITY);
        n_q->data.quantity.min = 1;
        n_q->data.quantity.max = -1;
        n_q->data.quantity.expr = n_p;
    }
    else if (match_character(input, '?')) {
        match_spaces(input);
        n_q = create_node(NODE_QUANTITY);
        n_q->data.quantity.min = 0;
        n_q->data.quantity.max = 1;
        n_q->data.quantity.expr = n_p;
    }
    else {
        n_q = n_p;
    }
    switch (t) {
    case '&':
        n_r = create_node(NODE_PREDICATE);
        n_r->data.predicate.neg = FALSE;
        n_r->data.predicate.expr = n_q;
        break;
    case '!':
        n_r = create_node(NODE_PREDICATE);
        n_r->data.predicate.neg = TRUE;
        n_r->data.predicate.expr = n_q;
        break;
    default:
        n_r = n_q;
    }
    if (match_character(input, '~')) {
        size_t p, l, m;
        match_spaces(input);
        p = input->bufcur;
        l = input->linenum;
        m = column_number(input);
        if (match_code_block(input)) {
            const size_t q = input->bufcur;
            match_spaces(input);
            n_t = create_node(NODE_ERROR);
            n_t->data.error.expr = n_r;
            n_t->data.error.code.text = strndup_e(input->buffer.buf + p + 1, q - p - 2);
            n_t->data.error.code.len = find_trailing_blanks(n_t->data.error.code.text);
            file_pos__set(&n_t->data.error.code.fpos, input->path, l, m);
            n_t->data.error.index = rule->data.rule.codes.len;
            node_const_array__add(&rule->data.rule.codes, n_t);
        }
        else {
            goto EXCEPTION;
        }
    }
    else {
        n_t = n_r;
    }
    return n_t;

EXCEPTION:;
    destroy_node(n_r);
    input->bufcur = p;
    input->linenum = l;
    input->charnum = n;
    input->linepos = o;
    return NULL;
}

static node_t *parse_sequence(input_state_t *input, node_t *rule) {
    const size_t p = input->bufcur;
    const size_t l = input->linenum;
    const size_t n = input->charnum;
    const size_t o = input->linepos;
    node_array_t *a_t = NULL;
    node_t *n_t = NULL;
    node_t *n_u = NULL;
    node_t *n_s = NULL;
    n_t = parse_term(input, rule);
    if (n_t == NULL) goto EXCEPTION;
    n_u = parse_term(input, rule);
    if (n_u != NULL) {
        n_s = create_node(NODE_SEQUENCE);
        a_t = &n_s->data.sequence.nodes;
        node_array__add(a_t, n_t);
        node_array__add(a_t, n_u);
        while ((n_t = parse_term(input, rule)) != NULL) {
            node_array__add(a_t, n_t);
        }
    }
    else {
        n_s = n_t;
    }
    return n_s;

EXCEPTION:;
    input->bufcur = p;
    input->linenum = l;
    input->charnum = n;
    input->linepos = o;
    return NULL;
}

static node_t *parse_expression(input_state_t *input, node_t *rule) {
    const size_t p = input->bufcur;
    const size_t l = input->linenum;
    const size_t n = input->charnum;
    const size_t o = input->linepos;
    size_t q;
    node_array_t *a_s = NULL;
    node_t *n_s = NULL;
    node_t *n_e = NULL;
    n_s = parse_sequence(input, rule);
    if (n_s == NULL) goto EXCEPTION;
    q = input->bufcur;
    if (match_character(input, '/')) {
        input->bufcur = q;
        n_e = create_node(NODE_ALTERNATE);
        a_s = &n_e->data.alternate.nodes;
        node_array__add(a_s, n_s);
        while (match_character(input, '/')) {
            match_spaces(input);
            n_s = parse_sequence(input, rule);
            if (n_s == NULL) goto EXCEPTION;
            node_array__add(a_s, n_s);
        }
    }
    else {
        n_e = n_s;
    }
    return n_e;

EXCEPTION:;
    destroy_node(n_e);
    input->bufcur = p;
    input->linenum = l;
    input->charnum = n;
    input->linepos = o;
    return NULL;
}

static node_t *parse_rule(input_state_t *input) {
    const size_t p = input->bufcur;
    const size_t l = input->linenum;
    const size_t m = column_number(input);
    const size_t n = input->charnum;
    const size_t o = input->linepos;
    size_t q;
    node_t *n_r = NULL;
    if (!match_identifier(input)) goto EXCEPTION;
    q = input->bufcur;
    match_spaces(input);
    if (!match_string(input, "<-")) goto EXCEPTION;
    match_spaces(input);
    n_r = create_node(NODE_RULE);
    n_r->data.rule.expr = parse_expression(input, n_r);
    if (n_r->data.rule.expr == NULL) goto EXCEPTION;
    assert(q >= p);
    n_r->data.rule.name = strndup_e(input->buffer.buf + p, q - p);
    file_pos__set(&n_r->data.rule.fpos, input->path, l, m);
    return n_r;

EXCEPTION:;
    destroy_node(n_r);
    input->bufcur = p;
    input->linenum = l;
    input->charnum = n;
    input->linepos = o;
    return NULL;
}

static const char *get_value_type(context_t *ctx) {
    return (ctx->vtype && ctx->vtype[0]) ? ctx->vtype : "int";
}

static const char *get_auxil_type(context_t *ctx) {
    return (ctx->atype && ctx->atype[0]) ? ctx->atype : "void *";
}

static const char *get_prefix(context_t *ctx) {
    return (ctx->prefix && ctx->prefix[0]) ? ctx->prefix : "pcc";
}

static void dump_options(context_t *ctx) {
    fprintf(stdout, "value_type: '%s'\n", get_value_type(ctx));
    fprintf(stdout, "auxil_type: '%s'\n", get_auxil_type(ctx));
    fprintf(stdout, "prefix: '%s'\n", get_prefix(ctx));
}

static bool_t parse_directive_block_(input_state_t *input, const char *name, code_block_array_t *output1, code_block_array_t *output2) {
    if (!match_string(input, name)) return FALSE;
    match_spaces(input);
    {
        const size_t p = input->bufcur;
        const size_t l = input->linenum;
        const size_t m = column_number(input);
        if (match_code_block(input)) {
            const size_t q = input->bufcur;
            match_spaces(input);
            if (output1 != NULL) {
                code_block_t *const c = code_block_array__create_entry(output1);
                c->text = strndup_e(input->buffer.buf + p + 1, q - p - 2);
                c->len = q - p - 2;
                file_pos__set(&c->fpos, input->path, l, m);
            }
            if (output2 != NULL) {
                code_block_t *const c = code_block_array__create_entry(output2);
                c->text = strndup_e(input->buffer.buf + p + 1, q - p - 2);
                c->len = q - p - 2;
                file_pos__set(&c->fpos, input->path, l, m);
            }
        }
        else {
            print_error("%s:" FMT_LU ":" FMT_LU ": Illegal %s syntax\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), name);
            input->errnum++;
        }
    }
    return TRUE;
}

static bool_t parse_directive_string_(input_state_t *input, const char *name, char **output, string_flag_t mode) {
    const size_t l = input->linenum;
    const size_t m = column_number(input);
    if (!match_string(input, name)) return FALSE;
    match_spaces(input);
    {
        char *s = NULL;
        const size_t p = input->bufcur;
        const size_t lv = input->linenum;
        const size_t mv = column_number(input);
        size_t q;
        if (match_quotation_single(input) || match_quotation_double(input)) {
            q = input->bufcur;
            match_spaces(input);
            s = strndup_e(input->buffer.buf + p + 1, q - p - 2);
            if (!unescape_string(s, FALSE)) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Illegal escape sequence\n", input->path, (ulong_t)(lv + 1), (ulong_t)(mv + 1));
                input->errnum++;
            }
        }
        else {
            print_error("%s:" FMT_LU ":" FMT_LU ": Illegal %s syntax\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), name);
            input->errnum++;
        }
        if (s != NULL) {
            string_flag_t f = STRING_FLAG__NONE;
            bool_t b = TRUE;
            remove_leading_blanks(s);
            remove_trailing_blanks(s);
            assert((mode & ~7) == 0);
            if ((mode & STRING_FLAG__NOTEMPTY) && !is_filled_string(s)) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Empty string\n", input->path, (ulong_t)(lv + 1), (ulong_t)(mv + 1));
                input->errnum++;
                f |= STRING_FLAG__NOTEMPTY;
            }
            if ((mode & STRING_FLAG__NOTVOID) && strcmp(s, "void") == 0) {
                print_error("%s:" FMT_LU ":" FMT_LU ": 'void' not allowed\n", input->path, (ulong_t)(lv + 1), (ulong_t)(mv + 1));
                input->errnum++;
                f |= STRING_FLAG__NOTVOID;
            }
            if ((mode & STRING_FLAG__IDENTIFIER) && !is_identifier_string(s)) {
                if (!(f & STRING_FLAG__NOTEMPTY)) {
                    print_error("%s:" FMT_LU ":" FMT_LU ": Invalid identifier\n", input->path, (ulong_t)(lv + 1), (ulong_t)(mv + 1));
                    input->errnum++;
                }
                f |= STRING_FLAG__IDENTIFIER;
            }
            if (output == NULL) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Definition of %s not allowed\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), name);
                input->errnum++;
                b = FALSE;
            }
            else if (*output != NULL) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Multiple definitions of %s\n", input->path, (ulong_t)(l + 1), (ulong_t)(m + 1), name);
                input->errnum++;
                b = FALSE;
            }
            if (f == STRING_FLAG__NONE && b) {
                assert(output != NULL);
                *output = s;
            }
            else {
                free(s); s = NULL;
            }
        }
    }
    return TRUE;
}

static bool_t parse_footer_(input_state_t *input, code_block_array_t *output) {
    if (!match_footer_start(input)) return FALSE;
    {
        const size_t p = input->bufcur;
        const size_t l = input->linenum;
        const size_t m = column_number(input);
        while (!match_eof(input)) match_character_any(input);
        {
            const size_t q = input->bufcur;
            code_block_t *const c = code_block_array__create_entry(output);
            c->text = strndup_e(input->buffer.buf + p, q - p);
            c->len = q - p;
            file_pos__set(&c->fpos, input->path, l, m);
        }
    }
    return TRUE;
}

static void parse_file_(context_t *ctx) {
    if (ctx->input == NULL) return;
    {
        file_id_t id;
        file_id__get(ctx->input->file, ctx->input->path, &id);
        if (!file_id_array__add_if_not_yet(&ctx->done, &id)) return; /* already imported */
    }
    {
        const bool_t imp = is_in_imported_input(ctx->input);
        bool_t b = TRUE;
        match_spaces(ctx->input);
        for (;;) {
            char *s = NULL;
            size_t l, m, n, o;
            if (match_eof(ctx->input) || parse_footer_(ctx->input, &ctx->fsource)) break;
            l = ctx->input->linenum;
            m = column_number(ctx->input);
            n = ctx->input->charnum;
            o = ctx->input->linepos;
            if (parse_directive_string_(ctx->input, "%import", &s, STRING_FLAG__NOTEMPTY)) {
                if (s) {
                    if (is_absolute_path(s)) {
                        FILE *const file = fopen(s, "rb");
                        if (file) {
                            ctx->input = create_input_state(s, file, ctx->input, &ctx->opts);
                            parse_file_(ctx);
                            ctx->input = destroy_input_state(ctx->input);
                        }
                        else {
                            if (errno != ENOENT) {
                                print_error(
                                    "%s:" FMT_LU ":" FMT_LU ": Cannot open file to read: %s\n",
                                    ctx->input->path, (ulong_t)(l + 1), (ulong_t)(m + 1),
                                    s
                                );
                            }
                            else {
                                print_error(
                                    "%s:" FMT_LU ":" FMT_LU ": File not found: %s\n",
                                    ctx->input->path, (ulong_t)(l + 1), (ulong_t)(m + 1),
                                    s
                                );
                            }
                            ctx->input->errnum++;
                        }
                    }
                    else {
                        size_t i = 0;
                        char *path = replace_filename(ctx->input->path, s);
                        FILE *file = fopen(path, "rb");
                        while (file == NULL) {
                            if (errno != ENOENT) {
                                print_error(
                                    "%s:" FMT_LU ":" FMT_LU ": Cannot open file to read: %s\n",
                                    ctx->input->path, (ulong_t)(l + 1), (ulong_t)(m + 1),
                                    path
                                );
                                ctx->input->errnum++;
                                break;
                            }
                            if (i >= ctx->dirs->len) {
                                print_error(
                                    "%s:" FMT_LU ":" FMT_LU ": File not found: %s\n",
                                    ctx->input->path, (ulong_t)(l + 1), (ulong_t)(m + 1),
                                    s
                                );
                                ctx->input->errnum++;
                                break;
                            }
                            free(path);
                            path = add_filename(ctx->dirs->buf[i++], s);
                            file = fopen(path, "rb");
                        }
                        if (file) {
                            ctx->input = create_input_state(path, file, ctx->input, &ctx->opts);
                            parse_file_(ctx);
                            ctx->input = destroy_input_state(ctx->input);
                        }
                        free(path);
                    }
                    free(s);
                }
                b = TRUE;
            }
            else if (
                parse_directive_block_(ctx->input, "%earlysource", &ctx->esource, NULL) ||
                parse_directive_block_(ctx->input, "%earlyheader", &ctx->eheader, NULL) ||
                parse_directive_block_(ctx->input, "%earlycommon", &ctx->esource, &ctx->eheader) ||
                parse_directive_block_(ctx->input, "%source", &ctx->source, NULL) ||
                parse_directive_block_(ctx->input, "%header", &ctx->header, NULL) ||
                parse_directive_block_(ctx->input, "%common", &ctx->source, &ctx->header) ||
                parse_directive_string_(ctx->input, "%value", imp ? NULL : &ctx->vtype, STRING_FLAG__NOTEMPTY | STRING_FLAG__NOTVOID) ||
                parse_directive_string_(ctx->input, "%auxil", imp ? NULL : &ctx->atype, STRING_FLAG__NOTEMPTY | STRING_FLAG__NOTVOID) ||
                parse_directive_string_(ctx->input, "%prefix", imp ? NULL : &ctx->prefix, STRING_FLAG__NOTEMPTY | STRING_FLAG__IDENTIFIER)
            ) {
                b = TRUE;
            }
            else if (match_character(ctx->input, '%')) {
                print_error("%s:" FMT_LU ":" FMT_LU ": Invalid directive\n", ctx->input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
                ctx->input->errnum++;
                match_identifier(ctx->input);
                match_spaces(ctx->input);
                b = TRUE;
            }
            else {
                node_t *const n_r = parse_rule(ctx->input);
                if (n_r == NULL) {
                    if (b) {
                        print_error("%s:" FMT_LU ":" FMT_LU ": Illegal rule syntax\n", ctx->input->path, (ulong_t)(l + 1), (ulong_t)(m + 1));
                        ctx->input->errnum++;
                        b = FALSE;
                    }
                    ctx->input->linenum = l;
                    ctx->input->charnum = n;
                    ctx->input->linepos = o;
                    if (!match_identifier(ctx->input) && !match_spaces(ctx->input)) match_character_any(ctx->input);
                    continue;
                }
                node_array__add(&ctx->rules, n_r);
                b = TRUE;
            }
            commit_buffer(ctx->input);
        }
        commit_buffer(ctx->input);
    }
    ctx->errnum += ctx->input->errnum;
    ctx->flags |= ctx->input->flags;
}

static bool_t parse(context_t *ctx) {
    parse_file_(ctx);
    make_rulehash(ctx);
    {
        size_t i;
        for (i = 0; i < ctx->rules.len; i++) {
            node_rule_t *const rule = &ctx->rules.buf[i]->data.rule;
            if (rule->ref < 0) {
                print_error(
                    "%s:" FMT_LU ":" FMT_LU ": Multiple definitions of rule: '%s'\n",
                    rule->fpos.path, (ulong_t)(rule->fpos.line + 1), (ulong_t)(rule->fpos.col + 1),
                    rule->name
                );
                ctx->errnum++;
                continue;
            }
            link_references(ctx, rule->expr);
        }
    }
    if (ctx->rules.len > 0)
        mark_rules_if_used(ctx, ctx->rules.buf[0]);
    {
        size_t i;
        for (i = 0; i < ctx->rules.len; i++) {
            if (!ctx->rules.buf[i]->data.rule.used)
                unreference_rules_from_unused_rule(ctx, ctx->rules.buf[i]);
        }
    }
    {
        size_t i, j;
        for (i = 0, j = 0; i < ctx->rules.len; i++) {
            if (!ctx->rules.buf[i]->data.rule.used)
                destroy_node(ctx->rules.buf[i]);
            else
                ctx->rules.buf[j++] = ctx->rules.buf[i];
        }
        ctx->rules.len = j;
    }
    {
        size_t i;
        for (i = 0; i < ctx->rules.len; i++) {
            const node_rule_t *const rule = &ctx->rules.buf[i]->data.rule;
            verify_variables(ctx, rule->expr, NULL);
            verify_captures(ctx, rule->expr, NULL);
        }
    }
    if (ctx->opts.debug) {
        size_t i;
        for (i = 0; i < ctx->rules.len; i++) {
            dump_node(ctx, ctx->rules.buf[i], 0);
        }
        dump_options(ctx);
    }
    return (ctx->errnum == 0) ? TRUE : FALSE;
}

static void print_indent(size_t depth)
{
    for(size_t indent = 0; indent < depth; indent++)
    {
        printf("\t");
    }
}

static char *print_string_with_escapes(char *string)
{
    size_t out_size = strlen(string) + 1;
    char *out_str = malloc(out_size);
    size_t in_index = 0;
    size_t out_index = 0;
    while(string[in_index])
    {
        switch(string[in_index])
        {
            case '\n':
                out_size++;
                out_str = realloc(out_str, out_size);
                out_str[out_index++] = '\\';
                out_str[out_index++] = 'n';
                break;

            case '\r':
                out_size++;
                out_str = realloc(out_str, out_size);
                out_str[out_index++] = '\\';
                out_str[out_index++] = 'r';
                break;

            case '\t':
                out_size++;
                out_str = realloc(out_str, out_size);
                out_str[out_index++] = '\\';
                out_str[out_index++] = 't';
                break;

            default:
                out_str[out_index++] = string[in_index];
                break;
        }

        in_index++;
    }

    out_str[out_index] = '\0';

    return out_str;
}

struct fuzz_results {
    char *in_str;
    string_array_t outputs;
};

typedef struct fuzz_results fuzz_results_t;

fuzz_results_t *create_new_fuzz_results(char *in_str)
{
    fuzz_results_t *wip_results = malloc(sizeof(fuzz_results_t));
    wip_results->in_str = in_str;
    string_array__init(&wip_results->outputs);

    return wip_results;
}

void fuzz_results_term(fuzz_results_t *results)
{
    string_array__term(&results->outputs);
    free(results);
}

void fuzz_results_add(fuzz_results_t *results, char *str)
{
    for(size_t scanned_idx = 0; scanned_idx < results->outputs.len; scanned_idx++)
    {
        char *existing_str = results->outputs.buf[scanned_idx];
        if(strcmp(existing_str, str) == 0)
        {
            return;
        }
    }
    // printf("add [%s]->[%s]\n", results->in_str, with_escape);
    string_array__add(&results->outputs, str, strlen(str));
}

fuzz_results_t *fuzz_results_merge(fuzz_results_t *a, fuzz_results_t *b)
{
    if(b != NULL)
    {
        for(size_t result_idx = 0; result_idx < b->outputs.len; result_idx++)
        {
            fuzz_results_add(a, b->outputs.buf[result_idx]);
        }

        fuzz_results_term(b);
    }
    return a;
}


void fuzz_results_print(fuzz_results_t *results)
{
    printf("Fuzz results for prefix string [%s]", results->in_str);
    for(size_t result_idx = 0; result_idx < results->outputs.len; result_idx++)
    {
        printf("%s\n", results->outputs.buf[result_idx]);
    }
}

bool_t is_string_all_whitespace(char *str)
{
    while(*str)
    {
        switch(*str)
        {
            case '\n':
            case '\r':
            case '\t':
            case ' ':
                break;

            default:
                return FALSE;
        }
        str++;
    }

    return TRUE;
}

size_t fuzz_results_filter(context_t *ctx, fuzz_results_t *results)
{
    size_t n_all_whitespace = 0;
    string_array_t passed_filter;
    string_array__init(&passed_filter);
    printf("Fuzz results for prefix string [%s]", results->in_str);
    for(size_t result_idx = 0; result_idx < results->outputs.len; result_idx++)
    {
        char *examined = results->outputs.buf[result_idx];
        int examined_len = strlen(examined);
        if(!is_string_all_whitespace(examined) && (examined_len > ctx->opts.minlen))
        {
            string_array__add(&passed_filter, examined, examined_len);
        }
        else
        {
            n_all_whitespace++;
        }
    }

    results->outputs.len = 0;
    for(size_t result_idx = 0; result_idx < passed_filter.len; result_idx++)
    {
        string_array__add(&results->outputs, passed_filter.buf[result_idx], strlen(passed_filter.buf[result_idx]));
    }

    return n_all_whitespace;
}


char *string_append(char *str, char *to_add)
{
    char *appended = malloc(strlen(str) + strlen(to_add) + 1);
    strcpy(appended, str);
    strcat(appended, to_add);

    free(str);
    return appended;
}

#define DEFAULT_MAX_EXPANSION_DEPTH 8
#define DEFAULT_MAX_STAR_EXPANSION 1
#define DEFAULT_MIN_FUZZ_LENGTH 5
// #define PRINT_DEPTH_LIMIT_EXCEEDED (deoth) print_indent(depth); printf("depth limit exceeded - abandon\n");
#define PRINT_DEPTH_LIMIT_EXCEEDED
#define CHECK_EXPANSION_DEPTH(depth, maxdepth) if((depth) > (maxdepth)) { PRINT_DEPTH_LIMIT_EXCEEDED(depth); return NULL;}

#define PRINT_EXPANSION
#define PRINT_DONE_EXPANSION

// #define PRINT_EXPANSION(depth, what) print_indent(depth); printf("Expand %s at depth %zu\n", what, depth);
// #define PRINT_DONE_EXPANSION(depth, what) print_indent(depth); printf("Done expanding %s at depth %zu\n", what, depth);


static fuzz_results_t *fuzz_expand(context_t *ctx, node_t *node, size_t depth, char *in_str);

static fuzz_results_t *fuzz_expand_rule(context_t *ctx, node_rule_t *rule, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "RULE");
    // printf("rule is %s\n", rule->name);

    fuzz_results_t *results = create_new_fuzz_results(in_str);

    results = fuzz_results_merge(results, fuzz_expand(ctx, rule->expr, depth, in_str));

    PRINT_DONE_EXPANSION(depth, "RULE");
    return results;
}

static fuzz_results_t *fuzz_expand_reference(context_t *ctx, node_reference_t *reference, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "REFERENCE");

    // printf("reference rule name is %d %s\n", reference->rule->type, reference->rule->data.rule.name);
    fuzz_results_t *results = fuzz_expand(ctx, (node_t *)reference->rule, depth, in_str);

    PRINT_DONE_EXPANSION(depth, "REFERENCE");
    return results;
}

static fuzz_results_t *fuzz_expand_string(context_t *ctx, node_string_t *string, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "STRING");

    fuzz_results_t *results = create_new_fuzz_results(in_str);

    char *result_str = string_append(strdup(in_str), string->value);
    fuzz_results_add(results, result_str);
    free(result_str);

    PRINT_DONE_EXPANSION(depth, "STRING");

    return results;
}

static fuzz_results_t *fuzz_expand_charclass(context_t *ctx, node_charclass_t *charclass, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "CHARCLASS");

    fuzz_results_t *results = create_new_fuzz_results(in_str);

    char *appended_char_string = string_append(strdup(in_str), " ");
    size_t char_index = strlen(in_str);

    char start;
    char end;
    // TODO: support inverse class matching ex. [^0-9]
    if(charclass->value == NULL)
    {
        start = '0';
        end = '~';

    }
    else
    {
        if(charclass->value[0] == '^')
        {
            // TODO: properly implement this
            start = '!';
            end = '!';
        }
        char start = charclass->value[0];
        char end = charclass->value[2];

        if(start > end)
        {
            start = charclass->value[2];
            end = charclass->value[0];
        }
    }

    if(ctx->opts.stochastic)
    {
        char rand_char = (rand() % ('~' - '0')) + '0';
        appended_char_string[char_index] = rand_char;
        fuzz_results_add(results, appended_char_string);
    }
    else
    {
        for(char any = start; any <= end; any++)
        {
            appended_char_string[char_index] = any;
            fuzz_results_add(results, appended_char_string);
        }
    }

    free(appended_char_string);

    PRINT_DONE_EXPANSION(depth, "CHARCLASS");
    return results;
}

static fuzz_results_t *fuzz_expand_quantity(context_t *ctx, node_quantity_t *quantity, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "QUANTITY");

    fuzz_results_t *results = create_new_fuzz_results(in_str);


    int min_count = quantity->min;
    int max_count = quantity->max;

    if(max_count == -1)
    {
        max_count = ctx->opts.maxstar;
    }

    int rand_count;
    if(ctx->opts.stochastic)
    {
        rand_count = rand() % ((max_count - min_count) + 1);
        rand_count += min_count;
    }

    // printf("QUANTITY - between %d and %d\n", min_count, max_count);

    fuzz_results_t *expr_results = fuzz_expand(ctx, quantity->expr, depth, "");

    if(expr_results != NULL)
    {
        for(size_t expr_result_idx = 0; expr_result_idx < expr_results->outputs.len; expr_result_idx++)
        {
            char *expr_output = expr_results->outputs.buf[expr_result_idx];
            char *result = strdup(in_str);

            if(ctx->opts.stochastic)
            {
                for(int count = 0; count < rand_count; count++)
                {
                    result = string_append(result, expr_output);
                }
                fuzz_results_add(results, result);
            }
            else
            {
                for(int count = 0; count < min_count - 1; count++)
                {
                    result = string_append(result, expr_output);
                }
                
                for(int count = min_count; count <= max_count; count++)
                {
                    result = string_append(result, expr_output);
                    fuzz_results_add(results, result);
                }
            }
            free(result);
        }

        fuzz_results_term(expr_results);
    }


    PRINT_DONE_EXPANSION(depth, "QUANTITY");
    return results;
}

static fuzz_results_t *fuzz_expand_predicate(context_t *ctx, node_predicate_t *predicate, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "PREDICATE");

    fuzz_results_t *results = create_new_fuzz_results(in_str);

    if(predicate->neg)
    {
        fuzz_results_add(results, in_str);
    }
    else
    {
        results = fuzz_results_merge(results, fuzz_expand(ctx, predicate->expr, depth, in_str));
    }


    PRINT_DONE_EXPANSION(depth, "PREDICATE");
    return results;
}

static fuzz_results_t *fuzz_expand_sequence(context_t *ctx, node_sequence_t *sequence, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "SEQUENCE");

    fuzz_results_t *results = create_new_fuzz_results(in_str);

    fuzz_results_add(results, in_str);

    for(size_t sequence_idx = 0; sequence_idx < sequence->nodes.len; sequence_idx++)
    {
        fuzz_results_t *new_results = create_new_fuzz_results(in_str);
        for(size_t result_idx = 0; result_idx < results->outputs.len; result_idx++)
        {
            // printf("Expanding index %zu of sequence from [%s]\n", sequence_idx, results->outputs.buf[result_idx]);
            fuzz_results_t *sequence_member_results = fuzz_expand(ctx, sequence->nodes.buf[sequence_idx], depth, results->outputs.buf[result_idx]);
            if(sequence_member_results == NULL)
            {
                // printf("abandon sequence\n");
                fuzz_results_term(new_results);
                fuzz_results_term(results);
                return NULL;
            }
            else
            {
                new_results = fuzz_results_merge(new_results, sequence_member_results);
            }
        }

        fuzz_results_term(results);
        results = new_results;
    }

    PRINT_DONE_EXPANSION(depth, "SEQUENCE");

    return results;
}

static fuzz_results_t *fuzz_expand_alternate(context_t *ctx, node_alternate_t *alternate, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "ALTERNATE");

    fuzz_results_t *results = create_new_fuzz_results(in_str);

    if(ctx->opts.stochastic)
    {
        size_t idx = rand() % alternate->nodes.len;
        results = fuzz_results_merge(results, fuzz_expand(ctx, alternate->nodes.buf[idx], depth, in_str));
    }
    else
    {
        for(size_t alternate_idx = 0; alternate_idx < alternate->nodes.len; alternate_idx++)
        {
            results = fuzz_results_merge(results, fuzz_expand(ctx, alternate->nodes.buf[alternate_idx], depth, in_str));
        }
    }

    PRINT_DONE_EXPANSION(depth, "ALTERNATE");
    return results;
}

static fuzz_results_t *fuzz_expand_capture(context_t *ctx, node_capture_t *capture, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "CAPTURE");

    fuzz_results_t *results = fuzz_expand(ctx, capture->expr, depth, in_str);

    PRINT_DONE_EXPANSION(depth, "CAPTURE");
    return results;
}

static fuzz_results_t *fuzz_expand_expand(context_t *ctx, node_expand_t *expand, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "EXPAND");

    fuzz_results_t *results = create_new_fuzz_results(in_str);
    fuzz_results_add(results, in_str);

    PRINT_DONE_EXPANSION(depth, "EXPAND");
    return results;
}

static fuzz_results_t *fuzz_expand_action(context_t *ctx, node_action_t *action, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "ACTION");

    fuzz_results_t *results = create_new_fuzz_results(in_str);
    fuzz_results_add(results, in_str);


    PRINT_DONE_EXPANSION(depth, "ACTION");
    return results;
}

static fuzz_results_t *fuzz_expand_error(context_t *ctx, node_error_t *error, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);
    PRINT_EXPANSION(depth, "ERROR");

    fuzz_results_t *results = create_new_fuzz_results(in_str);
    fuzz_results_add(results, in_str);

    PRINT_DONE_EXPANSION(depth, "ERROR");    
    return results;
}



static fuzz_results_t *fuzz_expand(context_t *ctx, node_t *node, size_t depth, char *in_str)
{
    CHECK_EXPANSION_DEPTH(depth, ctx->opts.maxdepth);

    fuzz_results_t *results = NULL;

    switch(node->type)
    {
        case NODE_RULE:
            results = fuzz_expand_rule(ctx, &node->data.rule, depth + 1, in_str);
            break;

        case NODE_REFERENCE:
            results = fuzz_expand_reference(ctx, &node->data.reference, depth + 1, in_str);
            break;

        case NODE_STRING:
            results = fuzz_expand_string(ctx, &node->data.string, depth + 1, in_str);
            break;

        case NODE_CHARCLASS:
            results = fuzz_expand_charclass(ctx, &node->data.charclass, depth + 1, in_str);
            break;

        case NODE_QUANTITY:
            results = fuzz_expand_quantity(ctx, &node->data.quantity, depth + 1, in_str);
            break;

        case NODE_PREDICATE:
            results = fuzz_expand_predicate(ctx, &node->data.predicate, depth + 1, in_str);
            break;

        case NODE_SEQUENCE:
            results = fuzz_expand_sequence(ctx, &node->data.sequence, depth + 1, in_str);
            break;

        case NODE_ALTERNATE:
            results = fuzz_expand_alternate(ctx, &node->data.alternate, depth + 1, in_str);
            break;

        case NODE_CAPTURE:
            results = fuzz_expand_capture(ctx, &node->data.capture, depth + 1, in_str);
            break;

        case NODE_EXPAND:
            results = fuzz_expand_expand(ctx, &node->data.expand, depth + 1, in_str);
            break;

        case NODE_ACTION:
            results = fuzz_expand_action(ctx, &node->data.action, depth + 1, in_str);
        break;

        case NODE_ERROR:
            results = fuzz_expand_error(ctx, &node->data.error, depth + 1, in_str);
        break;
    }

    return results;
}

#include "time.h"
static bool_t fuzz(context_t *ctx)
{
    srand(time(0));

    fuzz_results_t *results = create_new_fuzz_results("");

    for(size_t rule_idx = 0; rule_idx < ctx->rules.len; rule_idx++)
    {
        node_t *rule_node = ctx->rules.buf[rule_idx];
        if(rule_node->type != NODE_RULE)
        {
            print_error("Saw non-rule node type at rule index %zu\n", rule_idx);
            return FALSE;
        }
        results = fuzz_results_merge(results, fuzz_expand(ctx, rule_node, 0, ""));

        printf("\n");
    }

    size_t n_all_whitespace = fuzz_results_filter(ctx, results);
    printf("filtered %zu fuzz outputs which were all whitespace or didn't meet minimum length\n", n_all_whitespace);

    fuzz_results_print(results);

    fuzz_results_term(results);
}

static void print_version(FILE *output) {
    fprintf(output, "%s version %s\n", g_cmdname, VERSION);
    fprintf(output, "Copyright (c) 2014, 2019-2024 Arihiro Yoshida. All rights reserved.\n");
}

static void print_usage(FILE *output) {
    fprintf(output, "Usage: %s [OPTIONS] [FILE]\n", g_cmdname);
    fprintf(output, "Generates a packrat parser for C.\n");
    fprintf(output, "\n");
    fprintf(output, "Options:\n");
    fprintf(output, "  -o BASENAME    specify a base name of output source and header files;\n");
    fprintf(output, "                   can be used only once\n");
    fprintf(output, "  -I DIRNAME     specify a directory name to search for import files;\n");
    fprintf(output, "                   can be used as many times as needed to add directories\n");
    fprintf(output, "  -a, --ascii    disable UTF-8 support\n");
    fprintf(output, "  -l, --lines    add #line directives\n");
    fprintf(output, "  -d, --debug    with debug information\n");
    fprintf(output, "  -h, --help     print this help message and exit\n");
    fprintf(output, "  -v, --version  print the version and exit\n");
    fprintf(output, "\n");
    fprintf(output, "Environment Variable:\n");
    fprintf(output, "  %s\n", ENVVAR_IMPORT_PATH);
    fprintf(output, "      specify directory names to search for import files, delimited by '%c'\n", PATH_SEP);
    fprintf(output, "\n");
    fprintf(output, "Full documentation at: <%s>\n", WEBSITE);
}

int main(int argc, char **argv) {
#ifdef _MSC_VER
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
#endif
#endif
    g_cmdname = extract_filename(argv[0]);
    {
        const char *ipath = NULL;
        const char *opath = NULL;
        options_t opts = { 0 };
        string_array_t dirs;
        string_array__init(&dirs);
        opts.ascii = FALSE;
        opts.lines = FALSE;
        opts.debug = FALSE;
        {
            const char *path = NULL;
            const char *opt_o = NULL;
            bool_t opt_a = FALSE;
            bool_t opt_l = FALSE;
            bool_t opt_d = FALSE;
            bool_t opt_h = FALSE;
            bool_t opt_v = FALSE;
            bool_t opt_stochastic = FALSE;
            int opt_maxdepth = DEFAULT_MAX_EXPANSION_DEPTH;
            int opt_maxstar = DEFAULT_MAX_STAR_EXPANSION;
            int opt_minlen = DEFAULT_MIN_FUZZ_LENGTH;
            int i;
            for (i = 1; i < argc; i++) {
                if (argv[i][0] != '-') {
                    break;
                }
                else if (strcmp(argv[i], "--") == 0) {
                    i++; break;
                }
                else if (argv[i][1] == 'I') {
                    const char *const v = (argv[i][2] != '\0') ? argv[i] + 2 : (++i < argc) ?  argv[i] : NULL;
                    if (v == NULL || v[0] == '\0') {
                        print_error("Import directory name missing\n");
                        fprintf(stderr, "\n");
                        print_usage(stderr);
                        exit(1);
                    }
                    string_array__add(&dirs, v, VOID_VALUE);
                }
                else if (argv[i][1] == 'o') {
                    const char *const v = (argv[i][2] != '\0') ? argv[i] + 2 : (++i < argc) ?  argv[i] : NULL;
                    if (v == NULL || v[0] == '\0') {
                        print_error("Output base name missing\n");
                        fprintf(stderr, "\n");
                        print_usage(stderr);
                        exit(1);
                    }
                    if (opt_o != NULL) {
                        print_error("Extra output base name: '%s'\n", v);
                        fprintf(stderr, "\n");
                        print_usage(stderr);
                        exit(1);
                    }
                    opt_o = v;
                }
                else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--ascii") == 0) {
                    opt_a = TRUE;
                }
                else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--lines") == 0) {
                    opt_l = TRUE;
                }
                else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
                    opt_d = TRUE;
                }
                else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                    opt_h = TRUE;
                }
                else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
                    opt_v = TRUE;
                }
                else if (strcmp(argv[i], "--depth") == 0) {
                    const char *const v = (++i < argc) ?  argv[i] : NULL;
                    if (v == NULL || v[0] == '\0') {
                        print_error("Depth argument missing\n");
                        fprintf(stderr, "\n");
                        print_usage(stderr);
                        exit(1);
                    }
                    printf("got depth arg of %s\n", v);
                    opt_maxdepth = atoi(v);
                }
                else if (strcmp(argv[i], "--stochastic") == 0) {
                    opt_stochastic = TRUE;
                }
                else if (strcmp(argv[i], "--max-star") == 0) {
                    const char *const v = (++i < argc) ?  argv[i] : NULL;
                    printf("V:[%s]\n", v);
                    if (v == NULL || v[0] == '\0') {
                        print_error("Depth argument missing\n");
                        fprintf(stderr, "\n");
                        print_usage(stderr);
                        exit(1);
                    }
                    opt_maxstar = atoi(v);
                }
                else if (strcmp(argv[i], "--min-length") == 0) {
                    const char *const v = (++i < argc) ?  argv[i] : NULL;
                    printf("V:[%s]\n", v);
                    if (v == NULL || v[0] == '\0') {
                        print_error("Depth argument missing\n");
                        fprintf(stderr, "\n");
                        print_usage(stderr);
                        exit(1);
                    }
                    opt_minlen = atoi(v);
                }
                else {
                    print_error("Invalid option: '%s'\n", argv[i]);
                    fprintf(stderr, "\n");
                    print_usage(stderr);
                    exit(1);
                }
            }
            switch (argc - i) {
            case 0:
                break;
            case 1:
                path = argv[i];
                break;
            default:
                print_error("Extra input file: '%s'\n", argv[i + 1]);
                fprintf(stderr, "\n");
                print_usage(stderr);
                exit(1);
            }
            if (opt_h || opt_v) {
                if (opt_v) print_version(stdout);
                if (opt_v && opt_h) fprintf(stdout, "\n");
                if (opt_h) print_usage(stdout);
                exit(0);
            }
            ipath = (path && path[0]) ? path : NULL;
            opath = (opt_o && opt_o[0]) ? opt_o : NULL;
            opts.ascii = opt_a;
            opts.lines = opt_l;
            opts.debug = opt_d;
            opts.stochastic = opt_stochastic;
            opts.maxdepth = opt_maxdepth;
            opts.maxstar = opt_maxstar;
            opts.minlen = opt_minlen;
        }
        {
            const char *const v = getenv(ENVVAR_IMPORT_PATH);
            if (v) {
                size_t i = 0, h = 0;
                for (;;) {
                    if (v[i] == '\0') {
                        if (i > h) string_array__add(&dirs, v + h, i - h);
                        break;
                    }
                    else if (v[i] == PATH_SEP) {
                        if (i > h) string_array__add(&dirs, v + h, i - h);
                        h = i + 1;
                    }
                    i++;
                }
            }
        }
        {
            char *const s = get_home_directory();
            if (s) {
                char *const t = add_filename(s, IMPORT_DIR_USER);
                string_array__add(&dirs, t, VOID_VALUE);
                free(t);
                free(s);
            }
        }
        {
#ifdef _MSC_VER
            char *const s = get_appdata_directory();
            if (s) {
                char *const t = add_filename(s, IMPORT_DIR_SYSTEM);
                string_array__add(&dirs, t, VOID_VALUE);
                free(t);
                free(s);
            }
#else
            string_array__add(&dirs, IMPORT_DIR_SYSTEM, VOID_VALUE);
#endif
        }
        {
            context_t *const ctx = create_context(ipath, opath, &dirs, &opts);
            const int b = parse(ctx) && fuzz(ctx);
            destroy_context(ctx);
            if (!b) exit(10);
        }
        string_array__term(&dirs);
    }
    return 0;
}
