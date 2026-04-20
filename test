/*
 * comprehensive_cwe_test.c
 *
 * Single C source file demonstrating ALL CWE categories present in the
 * NIST Juliet C/C++ test suite (118 CWEs) PLUS real-world CWEs found in
 * production codebases (CWE-20, 22, 79, 89, 125, 200, 269, 285, 330,
 * 362, 787, 798, 918).
 *
 * Total CWEs covered: 131
 *
 * PURPOSE : Scanner validation and regression testing.
 * WARNING : This file is INTENTIONALLY VULNERABLE.
 *           Do NOT compile, run, or deploy.
 *
 * Structure:
 *   Section  1 — Buffer & Memory Safety        (CWE-121..789)
 *   Section  2 — Integer & Numeric Errors      (CWE-190..681)
 *   Section  3 — Injection                     (CWE-15, 78, 90, 114)
 *   Section  4 — Path Traversal                (CWE-23, 36)
 *   Section  5 — Cryptography Weaknesses       (CWE-256..780)
 *   Section  6 — Race Conditions & Concurrency (CWE-364..832)
 *   Section  7 — Information Exposure          (CWE-222..615)
 *   Section  8 — Resource Management           (CWE-252..775)
 *   Section  9 — Code Quality & Logic Errors   (CWE-176..843)
 *   Section 10 — Real-World Extras             (CWE-20..918)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dlfcn.h>


/* ============================================================================
 * SECTION 1 — BUFFER & MEMORY SAFETY
 * ============================================================================ */

/* CWE-121: Stack-Based Buffer Overflow */
void cwe121_stack_overflow(void) {
    char dest[10];
    char src[32] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    strcpy(dest, src);                          /* FLAW: src larger than dest */
}

/* CWE-122: Heap-Based Buffer Overflow */
void cwe122_heap_overflow(void) {
    char *buf = (char *)malloc(10);
    if (!buf) return;
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAA", 24); /* FLAW: write past heap allocation */
    free(buf);
}

/* CWE-123: Write-What-Where Condition */
void cwe123_write_what_where(int *user_ptr, int value) {
    *user_ptr = value;                          /* FLAW: unvalidated user-supplied pointer */
}

/* CWE-124: Buffer Underwrite */
void cwe124_buffer_underwrite(void) {
    char buf[20] = "hello";
    char *ptr = buf - 5;
    *ptr = 'A';                                 /* FLAW: write before buffer start */
}

/* CWE-126: Buffer Overread */
void cwe126_buffer_overread(void) {
    char dest[20];
    memset(dest, 'A', sizeof(dest));            /* no null terminator */
    char extra[] = "world";
    strcat(dest, extra);                        /* FLAW: reads past unterminated dest */
}

/* CWE-127: Buffer Underread */
void cwe127_buffer_underread(void) {
    char buf[20] = "hello";
    char *ptr = buf - 5;
    char c = *ptr;                              /* FLAW: read before buffer start */
    (void)c;
}

/* CWE-134: Uncontrolled Format String */
void cwe134_format_string(char *user_input) {
    printf(user_input);                         /* FLAW: user controls format string */
}

/* CWE-401: Memory Leak */
void cwe401_memory_leak(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    strcpy(buf, "data");
    if (buf[0] == 'd') return;                  /* FLAW: early return leaks buf */
    free(buf);
}

/* CWE-415: Double Free */
void cwe415_double_free(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    free(buf);
    free(buf);                                  /* FLAW: second free on same pointer */
}

/* CWE-416: Use After Free */
void cwe416_use_after_free(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "hello");
    free(buf);
    printf("%s\n", buf);                        /* FLAW: access after free */
}

/* CWE-457: Use of Uninitialized Variable */
int cwe457_uninitialized(int condition) {
    int result;                                 /* FLAW: no initializer */
    if (condition) result = 42;
    return result;                              /* FLAW: undefined if condition == 0 */
}

/* CWE-476: NULL Pointer Dereference */
void cwe476_null_deref(void) {
    char *ptr = NULL;
    strcpy(ptr, "hello");                       /* FLAW: dereference of NULL */
}

/* CWE-562: Return of Stack Variable Address */
char *cwe562_return_stack_addr(void) {
    char buf[64] = "stack data";
    return buf;                                 /* FLAW: dangling pointer to stack frame */
}

/* CWE-590: Free Memory Not on Heap */
void cwe590_free_stack(void) {
    char buf[64] = "stack buffer";
    free(buf);                                  /* FLAW: free() on stack variable */
}

/* CWE-680: Integer Overflow to Buffer Overflow */
void cwe680_int_overflow_to_buf(unsigned int user_len) {
    unsigned int alloc = user_len + 5;          /* FLAW: wraps around if user_len ~ UINT_MAX */
    char *buf = (char *)malloc(alloc);
    if (buf) { memset(buf, 0, user_len + 5); free(buf); }
}

/* CWE-761: Free Pointer Not at Start of Buffer */
void cwe761_free_not_start(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    buf += 10;
    free(buf);                                  /* FLAW: pointer offset from original alloc */
}

/* CWE-762: Mismatched Memory Management (C++ new / C free) */
void cwe762_mismatch_free_delete(void) {
    /* new[] paired with free() — mismatched allocator */
    /* char *buf = new char[64];  free(buf); */  /* FLAW (C++) */

    /* malloc() paired with delete — also mismatched */
    /* int *p = (int*)malloc(sizeof(int)); delete p; */ /* FLAW (C++) */
}

/* CWE-789: Uncontrolled Memory Allocation */
void cwe789_uncontrolled_alloc(size_t user_size) {
    char *buf = (char *)malloc(user_size);      /* FLAW: no upper bound on user_size */
    if (buf) free(buf);
}

/* ============================================================================
 * SECTION 2 — INTEGER & NUMERIC ERRORS
 * ============================================================================ */

/* CWE-190: Integer Overflow */
int cwe190_integer_overflow(int a, int b) {
    return a + b;                               /* FLAW: no overflow check before addition */
}

/* CWE-191: Integer Underflow */
unsigned int cwe191_underflow(unsigned int a, unsigned int b) {
    return a - b;                               /* FLAW: wraps to UINT_MAX if b > a */
}

/* CWE-194: Unexpected Sign Extension */
void cwe194_sign_extension(void) {
    char  c = -1;
    int   i = c;                                /* FLAW: sign-extended to 0xFFFFFFFF */
    char  buf[10];
    memset(buf, 0, (size_t)i);                  /* FLAW: i interpreted as huge size_t */
}

/* CWE-195: Signed-to-Unsigned Conversion Error */
void cwe195_signed_to_unsigned(int len) {
    char buf[256];
    if (len < 256) {
        memcpy(buf, "data", (size_t)len);       /* FLAW: negative len → massive copy */
    }
}

/* CWE-196: Unsigned-to-Signed Conversion Error */
void cwe196_unsigned_to_signed(unsigned int uval) {
    int sval = (int)uval;                       /* FLAW: large unsigned wraps to negative */
    if (sval > 0) {
        char *buf = (char *)malloc((size_t)sval);
        if (buf) free(buf);
    }
}

/* CWE-197: Numeric Truncation Error */
void cwe197_truncation(long long big_val) {
    int truncated = (int)big_val;               /* FLAW: high bits silently dropped */
    (void)truncated;
}

/* CWE-369: Divide by Zero */
int cwe369_divide_by_zero(int a, int b) {
    return a / b;                               /* FLAW: b may be zero, no check */
}

/* CWE-468: Incorrect Pointer Scaling */
void cwe468_pointer_scaling(void) {
    int arr[20];
    int *ptr = arr;
    ptr = ptr + (sizeof(int) * 3);              /* FLAW: ptr arithmetic already scales */
    *ptr = 42;
}

/* CWE-681: Incorrect Numeric Conversion */
void cwe681_bad_conversion(void) {
    double d = 1e18;
    int    i = (int)d;                          /* FLAW: value overflows int → UB */
    (void)i;
}

/* ============================================================================
 * SECTION 3 — INJECTION
 * ============================================================================ */

/* CWE-15: External Control of System or Configuration Setting */
void cwe15_config_control(char *hostname_from_network) {
    /* FLAW: externally-controlled value used to configure the system */
    /* SetComputerNameA(hostname_from_network); */
    sethostname(hostname_from_network, strlen(hostname_from_network));
}

/* CWE-78: OS Command Injection */
void cwe78_os_command_injection(char *user_input) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ls -la %s", user_input);
    system(cmd);                                /* FLAW: user input in system() call */
}

/* CWE-90: LDAP Injection */
void cwe90_ldap_injection(char *username) {
    char filter[256];
    /* FLAW: no LDAP special-character escaping */
    snprintf(filter, sizeof(filter), "(uid=%s)", username);
    /* ldap_search_s(ld, base, LDAP_SCOPE_SUB, filter, NULL, 0, &result); */
}

/* CWE-114: Process Control */
void cwe114_process_control(char *lib_from_user) {
    dlopen(lib_from_user, RTLD_LAZY);           /* FLAW: user-controlled library loaded */
}

/* CWE-606: Unchecked Loop Condition */
void cwe606_loop_condition(int user_max) {
    int i = 0;
    while (i != user_max) {                     /* FLAW: negative user_max → infinite loop */
        i++;
    }
}

/* ============================================================================
 * SECTION 4 — PATH TRAVERSAL
 * ============================================================================ */

/* CWE-23: Relative Path Traversal */
void cwe23_relative_path(char *filename) {
    char path[512];
    snprintf(path, sizeof(path), "uploads/%s", filename); /* FLAW: ../../etc/passwd */
    fopen(path, "r");
}

/* CWE-36: Absolute Path Traversal */
void cwe36_absolute_path(char *user_path) {
    fopen(user_path, "r");                      /* FLAW: user fully controls the path */
}

/* ============================================================================
 * SECTION 5 — CRYPTOGRAPHY WEAKNESSES
 * ============================================================================ */

/* CWE-256: Plaintext Storage of Password */
void cwe256_plaintext_password(void) {
    FILE *f = fopen("config.txt", "w");
    if (!f) return;
    fprintf(f, "password=mysecretpassword\n"); /* FLAW: credential stored in plaintext */
    fclose(f);
}

/* CWE-259: Use of Hard-Coded Password */
int cwe259_hardcoded_password(const char *input) {
    const char *password = "admin123";          /* FLAW: hardcoded credential */
    return strcmp(input, password) == 0;
}

/* CWE-321: Use of Hard-Coded Cryptographic Key */
void cwe321_hardcoded_key(void) {
    unsigned char key[] = {                     /* FLAW: static key in source */
        0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF
    };
    (void)key;
}

/* CWE-325: Missing Required Cryptographic Step */
void cwe325_missing_mac(void) {
    /* Encrypt data but never compute/verify HMAC */
    /* EVP_EncryptFinal_ex called — EVP_DigestSignFinal never called */
    /* FLAW: no integrity protection alongside encryption */
}

/* CWE-327: Use of Broken or Risky Cryptographic Algorithm */
void cwe327_weak_algorithm(void) {
    /* MD5 used for security hash / DES used for encryption */
    /* MD5_CTX ctx; MD5_Init(&ctx);  ... */    /* FLAW: MD5 is cryptographically broken */
    /* DES_key_schedule ks; DES_set_key_unchecked(&key, &ks); */ /* FLAW: 56-bit key */
}

/* CWE-328: Use of Reversible One-Way Hash */
void cwe328_reversible_hash(void) {
    /* SHA-1 used for password storage — rainbow tables exist */
    /* SHA1((unsigned char*)password, len, digest); */ /* FLAW */
}

/* CWE-338: Use of Cryptographically Weak PRNG */
void cwe338_weak_prng(void) {
    srand((unsigned)time(NULL));               /* FLAW: predictable seed */
    int token = rand() % 1000000;             /* FLAW: rand() not suitable for security */
    (void)token;
}

/* CWE-780: Use of RSA Algorithm Without OAEP */
void cwe780_rsa_no_oaep(void) {
    /* RSA_public_encrypt(len, src, dst, rsa, RSA_PKCS1_PADDING); */
    /* FLAW: PKCS#1 v1.5 padding; OAEP (RSA_PKCS1_OAEP_PADDING) required */
}

/* ============================================================================
 * SECTION 6 — RACE CONDITIONS & CONCURRENCY
 * ============================================================================ */

volatile int    g_shared_counter = 0;
pthread_mutex_t g_mutex          = PTHREAD_MUTEX_INITIALIZER;
char            g_signal_buf[256];

/* CWE-364: Signal Handler Race Condition */
void cwe364_signal_handler(int sig) {
    (void)sig;
    strcpy(g_signal_buf, "signal received");   /* FLAW: strcpy not async-signal-safe */
}

/* CWE-366: Race Condition Within Thread */
void *cwe366_race_thread(void *arg) {
    (void)arg;
    g_shared_counter++;                        /* FLAW: unsynchronized write */
    return NULL;
}

/* CWE-367: Time-of-Check Time-of-Use (TOCTOU) */
void cwe367_toctou(const char *path) {
    if (access(path, R_OK) == 0) {             /* CHECK: file readable? */
        /* attacker swaps file with symlink here */
        FILE *f = fopen(path, "r");            /* USE: FLAW — race window */
        if (f) fclose(f);
    }
}

/* CWE-479: Signal Handler Use of Non-Reentrant Function */
void cwe479_signal_nonreentrant(int sig) {
    (void)sig;
    printf("Signal caught\n");                 /* FLAW: printf not async-signal-safe */
}

/* CWE-667: Improper Locking */
void cwe667_improper_locking(void) {
    pthread_mutex_lock(&g_mutex);
    g_shared_counter++;
    if (g_shared_counter < 0) return;          /* FLAW: early return skips unlock */
    pthread_mutex_unlock(&g_mutex);
}

/* CWE-832: Unlock of Resource That Is Not Locked */
void cwe832_unlock_not_locked(void) {
    pthread_mutex_unlock(&g_mutex);            /* FLAW: unlock without prior lock */
}

/* ============================================================================
 * SECTION 7 — INFORMATION EXPOSURE
 * ============================================================================ */

/* CWE-222: Truncation of Security-Relevant Information */
void cwe222_log_truncation(void) {
    long long event_id = 9876543210LL;
    int  short_id = (int)event_id;             /* FLAW: audit ID truncated in log */
    printf("Event: %d\n", short_id);
}

/* CWE-223: Omission of Security-Relevant Information */
void cwe223_omission(int auth_result) {
    if (auth_result != 0) {
        /* FLAW: authentication failure is silently ignored — not logged */
    }
}

/* CWE-226: Sensitive Information Uncleared Before Release */
void cwe226_not_cleared(void) {
    char password[64];
    strcpy(password, "user_password_123");
    /* ... use password ... */
    /* FLAW: password buffer not zeroed with memset before leaving scope */
}

/* CWE-319: Cleartext Transmission of Sensitive Information */
void cwe319_cleartext_tx(int sock, const char *password) {
    send(sock, password, strlen(password), 0); /* FLAW: credential over plaintext socket */
}

/* CWE-526: Exposure of Sensitive Information via Environment Variables */
void cwe526_env_exposure(void) {
    char *secret = getenv("DB_PASSWORD");
    if (secret)
        printf("Config: %s\n", secret);        /* FLAW: env var printed to stdout */
}

/* CWE-534: Information Exposure Through Debug Log */
void cwe534_debug_log(const char *password) {
    fprintf(stderr, "[DEBUG] password=%s\n", password); /* FLAW: secret in log */
}

/* CWE-535: Information Exposure Through Shell Error Message */
void cwe535_shell_error(const char *cmd) {
    system(cmd);                               /* FLAW: shell errors expose file paths */
}

/* CWE-615: Information Exposure Through Comments */
/* TODO: remove admin backdoor key "letmein2024" before production */  /* FLAW */
void cwe615_info_in_comment(void) { }

/* ============================================================================
 * SECTION 8 — RESOURCE MANAGEMENT
 * ============================================================================ */

/* CWE-252: Unchecked Return Value */
void cwe252_unchecked_return(void) {
    char *buf = (char *)malloc(256);           /* FLAW: NULL not checked */
    strcpy(buf, "data");                       /* crashes if malloc returned NULL */
    free(buf);
}

/* CWE-253: Incorrect Check of Function Return Value */
void cwe253_incorrect_check(void) {
    FILE *f = fopen("file.txt", "r");
    if (f != (FILE *)1) {                      /* FLAW: wrong sentinel — should check NULL */
        /* f could still be NULL here */
    }
    if (f) fclose(f);
}

/* CWE-390: Error Without Action */
void cwe390_error_no_action(void) {
    int fd = open("/etc/shadow", O_RDONLY);
    if (fd < 0) { /* FLAW: error detected but no log, no return — execution continues */ }
    close(fd);
}

/* CWE-391: Unchecked Error Condition */
void cwe391_unchecked_error(int fd, char *buf, size_t n) {
    read(fd, buf, n);                          /* FLAW: return value not checked */
}

/* CWE-396: Catch of Base Exception Class (C++) */
/* try { risky(); } catch (std::exception &e) { } */  /* FLAW (C++): too broad */

/* CWE-397: Throw of Base Exception Class (C++) */
/* throw std::exception(); */                          /* FLAW (C++): too generic */

/* CWE-398: Poor Code Quality */
void cwe398_poor_quality(int x) {
    if (!!x == !(!x)) {                        /* FLAW: obfuscated tautology */
        printf("always true\n");
    }
}

/* CWE-400: Uncontrolled Resource Consumption */
void cwe400_resource_exhaustion(int user_count) {
    for (int i = 0; i < user_count; i++) {     /* FLAW: unbounded user-controlled loop */
        void *buf = malloc(4096);              /* FLAW: never freed — heap exhaustion */
        (void)buf;
    }
}

/* CWE-401: Memory Leak — additional pattern (resource handle) */
void cwe401_fd_leak(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    char buf[64];
    if (read(fd, buf, sizeof(buf)) < 0) return; /* FLAW: fd not closed on error path */
    close(fd);
}

/* CWE-404: Improper Resource Shutdown or Release */
void cwe404_improper_shutdown(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    char buf[64];
    read(fd, buf, sizeof(buf));
    if (buf[0] == 'E') return;                 /* FLAW: early return without close(fd) */
    close(fd);
}

/* CWE-459: Incomplete Cleanup */
void cwe459_incomplete_cleanup(void) {
    FILE *f   = fopen("tmp.dat", "w");
    char *buf = (char *)malloc(256);
    if (!f || !buf) {
        free(buf);                             /* FLAW: fclose never called if !f */
        return;
    }
    fwrite("data", 1, 4, f);
    free(buf);
    fclose(f);
}

/* CWE-666: Operation on Resource in Wrong Phase of Lifetime */
void cwe666_wrong_phase(int fd) {
    close(fd);
    char buf[16];
    read(fd, buf, sizeof(buf));                /* FLAW: read after close */
}

/* CWE-672: Operation on Resource After Expiration or Release */
void cwe672_after_release(void) {
    char *ptr = (char *)malloc(64);
    if (!ptr) return;
    free(ptr);
    memcpy(ptr, "data", 4);                    /* FLAW: use after free */
}

/* CWE-773: Missing Reference to Active File Descriptor */
void cwe773_missing_fd_ref(void) {
    int fd = open("a.txt", O_RDONLY);
    fd = open("b.txt", O_RDONLY);             /* FLAW: first fd overwritten — leaked */
    if (fd >= 0) close(fd);
}

/* CWE-775: Missing Release of File Descriptor or Handle */
void cwe775_fd_not_released(const char *path) {
    for (int i = 0; i < 65536; i++) {
        open(path, O_RDONLY);                  /* FLAW: fd opened but never closed */
    }
}

/* ============================================================================
 * SECTION 9 — CODE QUALITY & LOGIC ERRORS
 * ============================================================================ */

/* CWE-176: Improper Handling of Unicode or Internationalized Input */
void cwe176_unicode(const char *input) {
    char buf[16];
    strncpy(buf, input, 16);                   /* FLAW: multi-byte chars may be split */
}

/* CWE-188: Reliance on Data/Memory Layout */
int cwe188_memory_layout(void) {
    int arr[2] = {0x41424344, 0x45464748};
    char *raw = (char *)arr;
    return raw[0];                             /* FLAW: endianness-dependent behaviour */
}

/* CWE-242: Use of Inherently Dangerous Function */
void cwe242_dangerous_function(void) {
    char buf[64];
    gets(buf);                                 /* FLAW: gets() has no length limit */
}

/* CWE-244: Heap Inspection */
void cwe244_heap_inspection(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memset(buf, 0, 64);                        /* FLAW: only half cleared; rest leaks old data */
    free(buf);
}

/* CWE-247: Reliance on DNS Lookups in a Security Decision */
void cwe247_dns_security(const char *hostname) {
    struct hostent *h = gethostbyname(hostname); /* FLAW: DNS is spoofable */
    if (h && strcmp(h->h_name, "trusted.internal") == 0) {
        printf("Access granted\n");
    }
}

/* CWE-272: Least Privilege Violation */
void cwe272_least_privilege(void) {
    setuid(0);                                 /* FLAW: escalates to root permanently */
    setgid(0);
}

/* CWE-273: Improper Check for Dropped Privileges */
void cwe273_dropped_privilege(void) {
    setuid(1000);                              /* FLAW: return value not checked */
    system("ls /tmp");                         /* may still run as root if setuid failed */
}

/* CWE-284: Improper Access Control */
void cwe284_access_control(const char *role, const char *data) {
    /* FLAW: no authorisation check before writing sensitive data */
    printf("%s\n", data);
}

/* CWE-377: Insecure Temporary File */
void cwe377_insecure_tmp(void) {
    char *name = tmpnam(NULL);                 /* FLAW: predictable name, TOCTOU risk */
    FILE *f = fopen(name, "w");
    if (f) fclose(f);
}

/* CWE-398: already in Section 8 */

/* CWE-426: Untrusted Search Path */
void cwe426_untrusted_path(void) {
    system("python3 process.py");              /* FLAW: PATH may be attacker-controlled */
}

/* CWE-427: Uncontrolled Search Path Element */
void cwe427_search_path(void) {
    dlopen("libssl.so", RTLD_LAZY);            /* FLAW: LD_LIBRARY_PATH could redirect load */
}

/* CWE-440: Expected Behavior Violation */
int cwe440_behavior_violation(int *ptr) {
    if (!ptr) return -1;                       /* FLAW: API contract says return 0 on empty */
    return *ptr;
}

/* CWE-459: already in Section 8 */

/* CWE-464: Addition of Data Structure Sentinel */
void cwe464_sentinel_addition(char *str, size_t buf_size) {
    size_t len = strlen(str);
    str[len + 1] = '\0';                       /* FLAW: write one past the null terminator */
}

/* CWE-467: Use of sizeof() on a Pointer Type */
void cwe467_sizeof_pointer(void) {
    char *buf = (char *)malloc(sizeof(char *)); /* FLAW: allocates 4/8 bytes not 64 */
    strcpy(buf, "hello world — overflow");     /* overflow */
    free(buf);
}

/* CWE-469: Use of Pointer Subtraction to Determine Size */
void cwe469_ptr_subtraction(char *start, char *end) {
    int size = (int)(end - start);             /* FLAW: ptrdiff_t truncated to int on 64-bit */
    (void)size;
}

/* CWE-475: Undefined Behavior for Input to API */
void cwe475_undefined_api(void) {
    char *dst = NULL;
    memcpy(dst, "data", 4);                    /* FLAW: NULL destination to memcpy */
}

/* CWE-478: Missing Default Case in Switch Statement */
int cwe478_no_default(int code) {
    switch (code) {                            /* FLAW: unhandled values silently fall out */
        case 1: return 10;
        case 2: return 20;
    }
    return -1;
}

/* CWE-480: Use of Incorrect Operator */
void cwe480_wrong_operator(int x) {
    if (x = 5) {                               /* FLAW: assigns 5 instead of comparing */
        printf("five\n");
    }
}

/* CWE-481: Assigning Instead of Comparing */
int cwe481_assign_not_compare(int *p) {
    if (*p = 0) {                              /* FLAW: always assigns 0, always false */
        return 1;
    }
    return 0;
}

/* CWE-482: Comparing Instead of Assigning */
void cwe482_compare_not_assign(int *x) {
    *x == 5;                                   /* FLAW: comparison result discarded */
}

/* CWE-483: Incorrect Block Delimitation */
void cwe483_block_delimit(int flag) {
    if (flag)
        printf("flag is set\n");
        printf("always prints\n");             /* FLAW: misleading indentation, no braces */
}

/* CWE-484: Omitted Break Statement in Switch */
int cwe484_missing_break(int x) {
    switch (x) {
        case 1:
            printf("one\n");
                                               /* FLAW: falls through to case 2 */
        case 2:
            printf("two\n");
            break;
        case 3:
            printf("three\n");
            break;
    }
    return x;
}

/* CWE-500: Public Static Field Not Final (C equivalent: mutable global used as constant) */
int CWE500_MAX_USERS = 100;                    /* FLAW: should be const — writable by any code */

/* CWE-506: Embedded Malicious Code */
void cwe506_backdoor(const char *user, const char *pass) {
    if (strcmp(user, "r00t") == 0 &&
        strcmp(pass, "toor")  == 0) {          /* FLAW: hidden login */
        system("/bin/sh -i");
    }
}

/* CWE-510: Trapdoor */
void cwe510_trapdoor(unsigned int magic) {
    if (magic == 0xDEADBEEFU) {               /* FLAW: hidden trigger */
        system("id >> /tmp/.pwned");
    }
}

/* CWE-511: Logic Time Bomb */
void cwe511_time_bomb(void) {
    time_t     now = time(NULL);
    struct tm *t   = localtime(&now);
    if (t && t->tm_year + 1900 == 2026 &&
             t->tm_mon  + 1    == 12) {        /* FLAW: destructive activation on 2026-12 */
        system("rm -rf /tmp/app_data/*");
    }
}

/* CWE-526: already in Section 7 */

/* CWE-546: Suspicious Comment */
/* BACKDOOR: emergency override PIN is 7734 — remove before release */  /* FLAW */
/* FIXME: auth check disabled for load testing — uncomment in production */
void cwe546_suspicious_comment(void) { }

/* CWE-561: Dead Code */
int cwe561_dead_code(int x) {
    return x;
    x = x + 1;                                /* FLAW: unreachable code after return */
    return x;
}

/* CWE-563: Unused Variable */
void cwe563_unused_variable(int input) {
    int result = input * 2;                    /* FLAW: computed but never used */
    printf("processed\n");
}

/* CWE-570: Expression Is Always False */
void cwe570_always_false(int x) {
    if (x > 10 && x < 5) {                    /* FLAW: mutually exclusive conditions */
        printf("impossible\n");
    }
}

/* CWE-571: Expression Is Always True */
void cwe571_always_true(unsigned int x) {
    if (x >= 0) {                              /* FLAW: unsigned is always >= 0 */
        printf("always\n");
    }
}

/* CWE-587: Assignment of a Fixed Address to a Pointer */
void cwe587_fixed_address(void) {
    int *ptr = (int *)0xDEAD0000;              /* FLAW: hardcoded hardware address */
    *ptr = 42;
}

/* CWE-588: Attempt to Access Child of Non-Structure Pointer */
void cwe588_non_struct_ptr(void) {
    int x = 5;
    struct { int a; int b; } *ptr = (void *)&x; /* FLAW: x is not that struct */
    ptr->b = 99;                               /* writes out-of-bounds */
}

/* CWE-591: Sensitive Data Storage in Improperly Locked Memory */
void cwe591_unlocked_memory(void) {
    char *key = (char *)malloc(32);
    if (!key) return;
    memcpy(key, "SECRET_AES_KEY_0", 16);
    /* FLAW: mlock() not called — key may be paged to disk */
    memset(key, 0, 32);
    free(key);
}

/* CWE-605: Multiple Binds to the Same Port */
void cwe605_multi_bind(void) {
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    int s1 = socket(AF_INET, SOCK_STREAM, 0);
    int s2 = socket(AF_INET, SOCK_STREAM, 0);
    bind(s1, (struct sockaddr *)&addr, sizeof(addr));
    bind(s2, (struct sockaddr *)&addr, sizeof(addr)); /* FLAW: same port bound twice */
    close(s1); close(s2);
}

/* CWE-617: Reachable Assertion */
void cwe617_reachable_assert(int user_value) {
    assert(user_value != 0);                   /* FLAW: user-supplied input can trip assert */
}

/* CWE-620: Unverified Password Change */
void cwe620_unverified_pw_change(const char *new_pass) {
    /* FLAW: old password not verified before applying new one */
    FILE *f = fopen("/etc/app/shadow", "w");
    if (f) { fprintf(f, "%s\n", new_pass); fclose(f); }
}

/* CWE-665: Improper Initialization */
void cwe665_bad_init(void) {
    int arr[10];                               /* FLAW: uninitialized array */
    for (int i = 0; i < 10; i++)
        printf("%d ", arr[i]);                 /* reads garbage */
}

/* CWE-674: Uncontrolled Recursion */
void cwe674_recursion(unsigned int n) {
    cwe674_recursion(n + 1);                   /* FLAW: no base case — stack overflow */
}

/* CWE-675: Duplicate Operations on Resource */
void cwe675_duplicate_op(int fd) {
    close(fd);
    close(fd);                                 /* FLAW: double close */
}

/* CWE-676: Use of Potentially Dangerous Function */
void cwe676_dangerous_func(const char *src) {
    char dest[64];
    strcpy(dest,  src);                        /* FLAW: no bounds on copy */
    strcat(dest,  src);                        /* FLAW: may overflow dest */
    sprintf(dest, src);                        /* FLAW: format string from user */
}

/* CWE-685: Function Call with Incorrect Number of Arguments */
void cwe685_wrong_arg_count(void) {
    printf("%d %s\n", 42);                     /* FLAW: %s argument missing */
}

/* CWE-688: Function Call with Incorrect Variable or Reference as Argument */
void cwe688_wrong_variable(void) {
    int  len = 10;
    char src[20] = "hello";
    char dst[20];
    memcpy(dst, src, sizeof(src));             /* FLAW: should use len, not sizeof(src) */
}

/* CWE-690: Unchecked Return Value to NULL Pointer Dereference */
void cwe690_null_from_return(const char *input) {
    char *p = strstr(input, "key=");
    int   v = atoi(p + 4);                     /* FLAW: p may be NULL if "key=" absent */
    (void)v;
}

/* CWE-758: Reliance on Undefined, Unspecified, or Implementation-Defined Behavior */
void cwe758_undefined_behavior(void) {
    int x = INT_MAX;
    int y = x + 1;                             /* FLAW: signed overflow is UB in C */
    (void)y;
}

/* CWE-785: Path Manipulation Function Without Maximum-Sized Buffer */
void cwe785_realpath_no_max(const char *name) {
    char path[64];
    realpath(name, path);                      /* FLAW: output may exceed 64 bytes; use PATH_MAX */
}

/* CWE-835: Loop with Unreachable Exit Condition */
void cwe835_infinite_loop(int x) {
    while (x > 0) {                            /* FLAW: x never modified inside loop */
        printf("spinning\n");
    }
}

/* CWE-843: Type Confusion */
typedef struct { int  kind; int  i_val; } TypeA;
typedef struct { int  kind; double d_val; } TypeB;

void cwe843_type_confusion(void *ptr, int type) {
    if (type == 1) {
        TypeA *a = (TypeA *)ptr;
        printf("int: %d\n", a->i_val);
    } else {
        TypeB *b = (TypeB *)ptr;               /* FLAW: same ptr, different layout */
        printf("dbl: %f\n", b->d_val);
    }
}

/* ============================================================================
 * SECTION 10 — REAL-WORLD EXTRAS (beyond the Juliet catalogue)
 * ============================================================================ */

/* CWE-20: Improper Input Validation */
void cwe20_improper_validation(const char *age_str) {
    int age = atoi(age_str);                   /* FLAW: no range check, atoi returns 0 on error */
    char record[age];                          /* VLA with unchecked user-controlled size */
    (void)record;
}

/* CWE-22: Path Traversal (generic — complements CWE-23/36) */
void cwe22_path_traversal(const char *user_dir, const char *filename) {
    char path[512];
    snprintf(path, sizeof(path),               /* FLAW: no canonicalization */
             "/var/data/%s/%s", user_dir, filename);
    fopen(path, "r");
}

/* CWE-79: Cross-Site Scripting via HTTP response (C HTTP server) */
void cwe79_xss(int sock, const char *user_input) {
    char response[1024];
    snprintf(response, sizeof(response),
             "HTTP/1.0 200 OK\r\n"
             "Content-Type: text/html\r\n\r\n"
             "<html><body>Hello, %s!</body></html>",
             user_input);                      /* FLAW: unescaped user input in HTML */
    send(sock, response, strlen(response), 0);
}

/* CWE-89: SQL Injection */
void cwe89_sql_injection(const char *username, const char *password) {
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE name='%s' AND pass='%s'",
             username, password);              /* FLAW: ' OR '1'='1 bypasses auth */
    /* sqlite3_exec(db, query, NULL, NULL, NULL); */
}

/* CWE-125: Out-of-Bounds Read */
void cwe125_oob_read(int user_idx) {
    int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    printf("%d\n", arr[user_idx]);             /* FLAW: user_idx not bounds-checked */
}

/* CWE-200: Exposure of Sensitive Information to an Unauthorized Actor */
void cwe200_info_exposure(int sock) {
    char msg[256];
    snprintf(msg, sizeof(msg),
             "Error in %s:%d — %s",
             __FILE__, __LINE__, strerror(errno)); /* FLAW: internal paths/error details to client */
    send(sock, msg, strlen(msg), 0);
}

/* CWE-269: Improper Privilege Management */
void cwe269_privilege_mgmt(void) {
    setuid(0);                                 /* FLAW: elevates to root permanently */
    setgid(0);
    /* sensitive work */
    /* privilege never dropped back */
}

/* CWE-285: Improper Authorization */
void cwe285_improper_authz(const char *role, const char *resource) {
    /* FLAW: role is user-supplied — attacker sends role="admin" */
    if (strcmp(role, "admin") == 0) {
        printf("Access to %s granted\n", resource);
    }
}

/* CWE-330: Use of Insufficiently Random Values */
void cwe330_weak_random(char *session_token, int len) {
    srand(42);                                 /* FLAW: constant seed → deterministic output */
    for (int i = 0; i < len; i++)
        session_token[i] = (char)('a' + rand() % 26);
}

/* CWE-362: Race Condition (generic TOCTOU on shared state) */
static int g_balance = 1000;

void cwe362_race_condition(int amount) {
    if (g_balance >= amount) {                 /* CHECK — no lock held */
        /* context switch here: another thread drains g_balance */
        g_balance -= amount;                   /* USE  — FLAW: balance may now be negative */
    }
}

/* CWE-787: Out-of-Bounds Write */
void cwe787_oob_write(int user_idx, int value) {
    int arr[10] = {0};
    arr[user_idx] = value;                     /* FLAW: user_idx not validated */
}

/* CWE-798: Use of Hard-Coded Credentials */
void cwe798_hardcoded_creds(void) {
    const char *api_key = "sk-live-xK9mP2qR7nL4vT8cW3jY6"; /* FLAW: key in source */
    const char *db_pass = "Passw0rd!@#$";                   /* FLAW: DB password in source */
    (void)api_key;
    (void)db_pass;
}

/* CWE-918: Server-Side Request Forgery (SSRF) */
void cwe918_ssrf(int sock, const char *user_url) {
    char req[512];
    /* FLAW: user-controlled URL fetched server-side — reaches internal services */
    snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: internal\r\n\r\n", user_url);
    send(sock, req, strlen(req), 0);
}

/* ============================================================================
 * MAIN — standalone compilation / manual testing only
 * ============================================================================ */
int main(void) {
    printf("=== comprehensive_cwe_test.c ===\n");
    printf("Juliet CWEs covered : 118\n");
    printf("Real-world extras   :  13  (CWE-20,22,79,89,125,200,269,285,330,362,787,798,918)\n");
    printf("Total CWEs          : 131\n");
    printf("WARNING: DO NOT RUN — file is intentionally vulnerable.\n");
    return 0;
}

/*
 * vulnerable_app.c
 * 
 * Industry-Level CWE Vulnerability Demonstration File
 * FOR SECURITY RESEARCH / SAST TESTING ONLY
 *
 * CWEs demonstrated:
 *  CWE-120  Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
 *  CWE-121  Stack-based Buffer Overflow
 *  CWE-122  Heap-based Buffer Overflow
 *  CWE-125  Out-of-bounds Read
 *  CWE-126  Buffer Over-read
 *  CWE-134  Uncontrolled Format String
 *  CWE-190  Integer Overflow or Wraparound
 *  CWE-191  Integer Underflow
 *  CWE-195  Signed to Unsigned Conversion Error
 *  CWE-197  Numeric Truncation Error
 *  CWE-200  Exposure of Sensitive Information
 *  CWE-242  Use of Inherently Dangerous Function
 *  CWE-252  Unchecked Return Value
 *  CWE-253  Incorrect Check of Function Return Value
 *  CWE-269  Improper Privilege Management
 *  CWE-285  Improper Authorization
 *  CWE-319  Cleartext Transmission of Sensitive Information
 *  CWE-326  Inadequate Encryption Strength
 *  CWE-330  Use of Insufficiently Random Values
 *  CWE-362  Race Condition (TOCTOU)
 *  CWE-369  Divide by Zero
 *  CWE-377  Insecure Temporary File
 *  CWE-390  Detection of Error Condition Without Action
 *  CWE-391  Unchecked Error Condition
 *  CWE-400  Uncontrolled Resource Consumption
 *  CWE-401  Missing Release of Memory after Effective Lifetime (Memory Leak)
 *  CWE-415  Double Free
 *  CWE-416  Use After Free
 *  CWE-426  Untrusted Search Path
 *  CWE-457  Use of Uninitialized Variable
 *  CWE-467  Use of sizeof() on a Pointer Type
 *  CWE-468  Incorrect Pointer Scaling
 *  CWE-469  Use of Pointer Subtraction to Determine Size
 *  CWE-476  NULL Pointer Dereference
 *  CWE-489  Active Debug Code Left in Production
 *  CWE-506  Embedded Malicious Code (backdoor-style)
 *  CWE-561  Dead Code
 *  CWE-563  Assignment to Variable Without Use
 *  CWE-570  Expression is Always False
 *  CWE-571  Expression is Always True
 *  CWE-587  Assignment of a Fixed Address to a Pointer
 *  CWE-590  Free of Memory Not on the Heap
 *  CWE-665  Improper Initialization
 *  CWE-676  Use of Potentially Dangerous Function
 *  CWE-690  Unchecked Return Value to NULL Pointer Dereference
 *  CWE-704  Incorrect Type Conversion or Cast
 *  CWE-732  Incorrect Permission Assignment for Critical Resource
 *  CWE-758  Reliance on Undefined, Unspecified, or Implementation-Defined Behavior
 *  CWE-762  Mismatched Memory Management Routines
 *  CWE-785  Use of Path Manipulation Function without Maximum-sized Buffer
 *  CWE-789  Uncontrolled Memory Allocation
 *  CWE-805  Buffer Access with Incorrect Length Value
 *  CWE-824  Access of Uninitialized Pointer
 *  CWE-825  Expired Pointer Dereference
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

/* =========================================================
 * Global state / configuration
 * ========================================================= */

#define MAX_USERNAME   64
#define MAX_PASSWORD   32
#define MAX_BUFFER     256
#define MAX_USERS      100
#define LOG_FILE       "/tmp/app.log"
#define TMP_LOCK_FILE  "/tmp/app.lock"

/* CWE-200: Sensitive data stored in plaintext globals */
static char g_admin_password[MAX_PASSWORD] = "Admin@1234!";   /* hardcoded secret */
static char g_db_conn_string[256]          = "host=10.0.0.1 user=root password=rootpass dbname=prod";

/* CWE-489: Debug flag left in production build */
static int  g_debug_mode = 1;

/* CWE-665: Improperly initialised global buffer */
static char g_session_token[128];   /* never zero-initialised before use */

typedef struct {
    int    id;
    char   username[MAX_USERNAME];
    char   password[MAX_PASSWORD];
    int    privilege_level;
    char  *profile_data;     /* heap-allocated */
} User;

typedef struct {
    char  filename[256];
    int   size;
    char *data;
} FileRecord;

/* Global user table – no bounds enforcement */
static User  g_users[MAX_USERS];
static int   g_user_count = 0;

/* Mutex used in race-condition demo */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;


/* =========================================================
 * Forward declarations
 * ========================================================= */
void  log_message(const char *fmt, ...);
int   authenticate_user(const char *username, const char *password);
void  process_user_input(char *input);
void  handle_file_upload(const char *filename, size_t size);
int   parse_packet(unsigned char *data, int len);
void *worker_thread(void *arg);
void  generate_report(const char *template_str);
int   calculate_checksum(int *arr, int count);
void  load_plugin(const char *path);
void  handle_request(int sock_fd);
int   validate_index(int idx, int max);


/* =========================================================
 * CWE-134: Uncontrolled Format String
 * CWE-200: Information Exposure via log
 * ========================================================= */
void log_message(const char *fmt, ...)
{
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        /* CWE-134: user-supplied fmt passed directly to fprintf */
        fprintf(fp, fmt);           /* VULN: should use fprintf(fp, "%s", fmt) */
        fclose(fp);
    }

    if (g_debug_mode) {
        /* CWE-134 again on stdout */
        printf(fmt);                /* VULN */
        /* CWE-200: prints internal connection string to console */
        printf("[DEBUG] DB conn: %s\n", g_db_conn_string);
    }
}


/* =========================================================
 * CWE-120 / CWE-121: Stack-based Buffer Overflow
 * CWE-242: Use of inherently dangerous function (gets, strcpy)
 * CWE-676: Use of potentially dangerous function (sprintf w/o limit)
 * ========================================================= */
void get_username(char *output)
{
    char local_buf[16];

    /* CWE-242 / CWE-121: gets() has no bounds – classic stack smash */
    gets(local_buf);                /* VULN: never use gets() */

    /* CWE-120: strcpy without size check */
    strcpy(output, local_buf);      /* VULN: output could be smaller than local_buf */
}

void build_query(const char *table, const char *condition)
{
    char query[128];

    /* CWE-676 / CWE-120: sprintf with user-controlled inputs, no length limit */
    sprintf(query, "SELECT * FROM %s WHERE %s", table, condition); /* VULN */

    log_message(query);             /* CWE-134: forwarding to format-string sink */
}


/* =========================================================
 * CWE-122: Heap-based Buffer Overflow
 * CWE-401: Memory Leak
 * CWE-415: Double Free
 * CWE-416: Use After Free
 * ========================================================= */
char *create_user_buffer(int requested_size)
{
    /* CWE-190: integer overflow – if requested_size is INT_MAX, +1 wraps to 0 */
    int alloc_size = requested_size + 1;    /* VULN */

    /* CWE-789: allocation size comes straight from user with no cap */
    char *buf = (char *)malloc(alloc_size); /* VULN */

    /* CWE-252: return value of malloc not checked */
    return buf;                             /* may be NULL */
}

void process_records(int count)
{
    char **records = (char **)malloc(count * sizeof(char *));
    if (!records) return;

    for (int i = 0; i < count; i++) {
        records[i] = (char *)malloc(MAX_BUFFER);
        if (records[i]) {
            memset(records[i], 0, MAX_BUFFER);
        }
    }

    /* Do some work */
    records[0][0] = 'A';

    /* CWE-415: double free */
    free(records[0]);
    free(records[0]);               /* VULN: second free on same pointer */

    /* CWE-416: use after free */
    records[1][0] = 'B';            /* VULN: may have been freed by allocator */

    /* CWE-401: memory leak – records[2..count-1] never freed */
    free(records);
}

void reallocate_buffer(User *u, size_t new_size)
{
    /* CWE-401: original pointer overwritten; if realloc fails, old memory leaks */
    u->profile_data = (char *)realloc(u->profile_data, new_size); /* VULN */
    if (!u->profile_data) {
        /* pointer is now NULL – old allocation lost */
        return;
    }
}


/* =========================================================
 * CWE-190 / CWE-191: Integer Overflow / Underflow
 * CWE-195: Signed-to-unsigned conversion
 * CWE-197: Numeric truncation
 * CWE-369: Divide by zero
 * ========================================================= */
size_t compute_allocation_size(int num_elements, int element_size)
{
    /* CWE-190: multiplication overflow when both operands are large */
    return (size_t)(num_elements * element_size); /* VULN: intermediate overflow */
}

void process_array(int *arr, int len)
{
    int total = 0;

    /* CWE-191: len could be negative; loop runs backwards / not at all */
    for (int i = 0; i < len; i++) {   /* VULN: no check for len < 0 */
        total += arr[i];
    }

    /* CWE-369: division without zero-check */
    int average = total / len;        /* VULN: divide by zero if len == 0 */

    printf("Average: %d\n", average);
}

short truncate_value(int val)
{
    /* CWE-197: truncation – high bits silently discarded */
    return (short)val;               /* VULN */
}

void signed_unsigned_confusion(int user_len)
{
    char buf[MAX_BUFFER];

    /* CWE-195: user_len is signed; if negative it passes size check but
     * converts to huge size_t in memcpy                                 */
    if (user_len < MAX_BUFFER) {
        memcpy(buf, "data", (size_t)user_len); /* VULN: size_t(-1) = HUGE */
    }
}


/* =========================================================
 * CWE-125 / CWE-126: Out-of-bounds Read
 * CWE-805: Buffer access with incorrect length value
 * ========================================================= */
int search_buffer(const char *haystack, int haystack_len,
                  const char *needle,   int needle_len)
{
    /* CWE-125: loop goes one past end of haystack */
    for (int i = 0; i <= haystack_len; i++) {  /* VULN: should be i < haystack_len */
        if (haystack[i] == needle[0]) {
            /* CWE-805: compare needle_len bytes without verifying remaining space */
            if (memcmp(&haystack[i], needle, needle_len) == 0) { /* VULN */
                return i;
            }
        }
    }
    return -1;
}

void copy_partial(char *dst, const char *src, int src_len)
{
    char tmp[64];

    /* CWE-126: strncpy reads src_len bytes even if src_len > strlen(src) */
    strncpy(tmp, src, src_len);   /* VULN: no NUL guarantee, may over-read */
    tmp[63] = '\0';
    strcpy(dst, tmp);             /* CWE-120: dst size unknown */
}


/* =========================================================
 * CWE-457: Use of Uninitialized Variable
 * CWE-824: Access of Uninitialized Pointer
 * CWE-825: Expired Pointer Dereference
 * ========================================================= */
int get_next_token(const char *input)
{
    int token;     /* CWE-457: never initialized before conditional use */
    int result;

    result = sscanf(input, "%d", &result);
    if (result == 1) {
        token = result;
    }
    /* token may be uninitialised if sscanf returned != 1 */
    return token;  /* VULN */
}

char *get_temp_pointer(void)
{
    char local_array[32] = "temporary data";
    return local_array;  /* CWE-825: returning pointer to stack – expired after return */
}

void use_uninitialised_ptr(void)
{
    char *ptr;           /* CWE-824: uninitialized pointer */
    /* ... some conditional logic that sometimes sets ptr ... */
    int condition = rand() % 2;
    if (condition) {
        ptr = (char *)malloc(64);
    }
    /* CWE-824: ptr used without guarantee it was initialized */
    strcpy(ptr, "hello"); /* VULN */
    free(ptr);
}


/* =========================================================
 * CWE-476: NULL Pointer Dereference
 * CWE-690: Unchecked return value → NULL dereference
 * ========================================================= */
void process_user_input(char *input)
{
    /* CWE-476: no NULL check on input before dereference */
    int len = strlen(input);        /* VULN: crashes if input == NULL */

    char *dup = strdup(input);
    /* CWE-690: strdup return not checked; dup may be NULL */
    dup[0] = toupper((unsigned char)dup[0]); /* VULN: NULL dereference */

    free(dup);
}

User *find_user(int id)
{
    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].id == id)
            return &g_users[i];
    }
    return NULL;
}

void update_user_privilege(int user_id, int new_priv)
{
    User *u = find_user(user_id);
    /* CWE-476: no NULL check */
    u->privilege_level = new_priv;  /* VULN: crashes if user not found */
}


/* =========================================================
 * CWE-362: Race Condition / TOCTOU
 * CWE-377: Insecure Temporary File
 * CWE-732: Incorrect Permission Assignment
 * ========================================================= */
int open_config_file(const char *path)
{
    struct stat st;

    /* CWE-362 / TOCTOU: check then use – window for attacker to swap file */
    if (stat(path, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            int fd = open(path, O_RDONLY); /* VULN: path may have changed */
            return fd;
        }
    }
    return -1;
}

void create_temp_file(void)
{
    /* CWE-377: predictable temp file name, no O_EXCL */
    char tmp_path[64];
    sprintf(tmp_path, "/tmp/app_tmp_%d", getpid());  /* predictable */
    int fd = open(tmp_path, O_CREAT | O_WRONLY, 0666); /* CWE-732: world-writable */
    if (fd >= 0) {
        write(fd, "lock", 4);
        close(fd);
    }
}

void *worker_thread(void *arg)
{
    /* CWE-362: accesses g_user_count without holding lock */
    int count = g_user_count;           /* VULN: torn read */
    for (int i = 0; i < count; i++) {
        /* process g_users[i] without lock */
        printf("Processing user %d\n", g_users[i].id);
    }
    return NULL;
}


/* =========================================================
 * CWE-330: Insufficient Randomness
 * CWE-326: Inadequate Encryption Strength
 * CWE-319: Cleartext Transmission
 * ========================================================= */
void generate_session_token(char *token_out, size_t len)
{
    /* CWE-330: seeded with time() – predictable */
    srand((unsigned int)time(NULL));   /* VULN */
    for (size_t i = 0; i < len - 1; i++) {
        token_out[i] = 'a' + (rand() % 26); /* VULN: low-entropy */
    }
    token_out[len - 1] = '\0';
}

void weak_encrypt(const char *plaintext, char *ciphertext)
{
    /* CWE-326: XOR with a single byte key – trivially broken */
    char key = 0x42;
    size_t len = strlen(plaintext);
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = plaintext[i] ^ key; /* VULN */
    }
    ciphertext[len] = '\0';
}

void send_credentials(int sock, const char *user, const char *pass)
{
    char payload[MAX_BUFFER];
    /* CWE-319: credentials sent in cleartext (no TLS) */
    snprintf(payload, sizeof(payload), "USER=%s PASS=%s", user, pass);
    send(sock, payload, strlen(payload), 0); /* VULN: cleartext over network */
}


/* =========================================================
 * CWE-285 / CWE-269: Improper Authorization / Privilege Management
 * ========================================================= */
int authenticate_user(const char *username, const char *password)
{
    /* CWE-285: no rate-limiting, no lockout – brute-force possible */
    for (int i = 0; i < g_user_count; i++) {
        /* CWE-326: plaintext password comparison */
        if (strcmp(g_users[i].username, username) == 0 &&
            strcmp(g_users[i].password, password) == 0) {
            return g_users[i].id;
        }
    }

    /* CWE-200: error message reveals whether username or password is wrong */
    if (g_debug_mode) {
        printf("Auth failed for user '%s'\n", username); /* VULN */
    }
    return -1;
}

void elevate_to_root(void)
{
    /* CWE-269: unconditionally elevates to UID 0 */
    setuid(0);   /* VULN: no check of return value, no authorisation gate */
    setgid(0);
}

void run_admin_command(int user_id, const char *cmd)
{
    User *u = find_user(user_id);
    /* CWE-285: privilege check uses data from untrusted source without
     *          server-side re-validation                               */
    if (u != NULL) {
        /* Should verify u->privilege_level == ADMIN, but just runs cmd */
        system(cmd);   /* CWE-78: OS command injection + CWE-285 */  /* VULN */
    }
}


/* =========================================================
 * CWE-252 / CWE-253: Unchecked / Incorrectly Checked Return Values
 * CWE-390 / CWE-391: Error Detection Without Action
 * ========================================================= */
void write_audit_record(const char *record)
{
    FILE *fp = fopen(LOG_FILE, "a");
    /* CWE-252: fopen return value not checked */
    fputs(record, fp);              /* VULN: crashes if fp == NULL */
    fclose(fp);
}

int read_config(const char *path)
{
    char buf[512];
    int  fd = open(path, O_RDONLY);
    /* CWE-253: error code checked but then silently ignored */
    if (fd == -1) {
        /* CWE-390: error detected but not handled – continues anyway */
        errno = 0;  /* VULN: erasing error indicator */
    }

    /* CWE-391: read return value not checked – buf may be uninitialised */
    read(fd, buf, sizeof(buf) - 1); /* VULN */
    buf[511] = '\0';
    printf("Config: %s\n", buf);
    close(fd);
    return 0;
}


/* =========================================================
 * CWE-400: Uncontrolled Resource Consumption
 * CWE-789: Uncontrolled Memory Allocation
 * ========================================================= */
void handle_file_upload(const char *filename, size_t size)
{
    /* CWE-400 / CWE-789: no cap on size – caller can exhaust heap */
    char *buf = (char *)malloc(size);     /* VULN: size up to SIZE_MAX */
    if (!buf) return;

    FILE *fp = fopen(filename, "rb");
    if (fp) {
        /* CWE-400: reads up to 'size' bytes unchecked */
        fread(buf, 1, size, fp);          /* VULN */
        fclose(fp);
    }
    free(buf);
}

void allocate_connection_pool(int num_connections)
{
    /* CWE-400: num_connections from user, no upper bound */
    int *pool = (int *)malloc(sizeof(int) * num_connections); /* VULN */
    if (!pool) return;

    for (int i = 0; i < num_connections; i++) {
        pool[i] = socket(AF_INET, SOCK_STREAM, 0);
        /* CWE-401: sockets never closed on error path */
    }
    free(pool);
}


/* =========================================================
 * CWE-426: Untrusted Search Path
 * CWE-506: Embedded Backdoor (hardcoded credential bypass)
 * ========================================================= */
void load_plugin(const char *name)
{
    char cmd[256];
    /* CWE-426: PATH not sanitised – attacker can shadow 'dlopen' wrapper */
    snprintf(cmd, sizeof(cmd), "loadmod %s", name);
    system(cmd);  /* VULN */
}

int backdoor_check(const char *password)
{
    /* CWE-506: hardcoded backdoor credential */
    if (strcmp(password, "LetM3In!BackD00r") == 0) { /* VULN */
        elevate_to_root();
        return 1;
    }
    return 0;
}


/* =========================================================
 * CWE-467: sizeof on pointer type
 * CWE-468: Incorrect pointer scaling
 * CWE-469: Pointer subtraction to determine size
 * CWE-704: Incorrect type conversion
 * ========================================================= */
void pointer_mistakes(void)
{
    int arr[10];
    int *ptr = arr;

    /* CWE-467: sizeof(ptr) == 8 (pointer size), not sizeof(arr) == 40 */
    memset(ptr, 0, sizeof(ptr));    /* VULN: only zeroes 8 bytes */

    /* CWE-468: pointer arithmetic scaled by sizeof(int), not sizeof(char) */
    char *cptr = (char *)arr;
    char *wrong = (char *)(ptr + 1); /* VULN: jumps 4 bytes, not 1 */
    (void)wrong;

    /* CWE-469: pointer subtraction – only valid for same array */
    int  another[10];
    ptrdiff_t diff = another - arr;  /* VULN: undefined behaviour */
    (void)diff;
}

void type_conversion_errors(void)
{
    long long big_val = 0x1FFFFFFFF;
    /* CWE-704: data truncated silently */
    int  small = (int)big_val;      /* VULN */
    char tiny  = (char)big_val;     /* VULN */

    unsigned int u = 0;
    /* CWE-191: underflow */
    u--;    /* VULN: wraps to UINT_MAX */

    printf("%d %d %u\n", small, tiny, u);
}


/* =========================================================
 * CWE-562 / CWE-587: Fixed address / dangling reference
 * CWE-758: Undefined behaviour
 * CWE-762: Mismatched memory management routines
 * ========================================================= */
void fixed_address_access(void)
{
    /* CWE-587: assigning fixed (hardware) address – unsafe on modern OS */
    volatile int *reg = (volatile int *)0xDEADBEEF; /* VULN */
    *reg = 1;
}

void mismatched_free(void)
{
    char stack_buf[32] = "stack data";
    char *heap_buf = (char *)malloc(32);

    strcpy(heap_buf, "heap data");

    /* CWE-590: free of stack memory */
    free(stack_buf);     /* VULN: undefined behaviour */

    /* CWE-762: new/delete vs malloc/free mismatch (conceptual in C context:
     * free with wrong deallocator)                                         */
    free(heap_buf);      /* correct */
    free(heap_buf);      /* CWE-415: double free */
}

void undefined_behaviour_demo(void)
{
    /* CWE-758: signed integer overflow is UB in C */
    int x = INT_MAX;
    int y = x + 1;         /* VULN: undefined behaviour */
    (void)y;

    /* CWE-758: left-shift into sign bit */
    int shifted = 1 << 31; /* VULN: UB in C89/C99 */
    (void)shifted;

    /* CWE-758: dereferencing null */
    int *np = NULL;
    /* *np = 42; */   /* commented to prevent immediate crash but pattern is there */
}


/* =========================================================
 * CWE-785: Path manipulation without max-sized buffer
 * CWE-22: Path Traversal (bonus)
 * ========================================================= */
void build_file_path(const char *user_dir, const char *filename)
{
    char path[64];  /* CWE-785: too small for realpath output (need PATH_MAX=4096) */

    /* CWE-22: no sanitisation of filename – "../../../etc/passwd" works */
    snprintf(path, sizeof(path), "/uploads/%s/%s", user_dir, filename); /* VULN */

    FILE *fp = fopen(path, "r");
    if (fp) {
        char content[256];
        /* CWE-134: content from file piped to printf */
        fgets(content, sizeof(content), fp);
        printf(content); /* VULN */
        fclose(fp);
    }
}


/* =========================================================
 * CWE-561: Dead Code
 * CWE-563: Assignment without use
 * CWE-570/571: Always False/True conditions
 * ========================================================= */
int dead_code_demo(int x)
{
    int result = 0;
    result = 42;    /* CWE-563: assigned but never used after this */

    /* CWE-571: always true */
    if (1 == 1) {   /* VULN */
        result = x * 2;
    }

    /* CWE-570: always false – code below is dead */
    if (0) {        /* VULN */
        result = -1;  /* CWE-561: dead code */
        printf("This never executes\n");
    }

    return result;
}


/* =========================================================
 * CWE-665: Improper Initialisation
 * CWE-457: Uninitialized variable used conditionally
 * ========================================================= */
int compute_hash(const char *data, int len)
{
    int hash;   /* CWE-457/665: uninitialized – indeterminate value */
    int i;

    for (i = 0; i < len; i++) {
        hash ^= data[i];  /* VULN: hash starts with garbage */
    }
    return hash;
}

void init_user(User *u, int id, const char *name)
{
    /* CWE-665: struct not zeroed; password field left with stack garbage */
    u->id              = id;
    /* username set below, but password and profile_data NOT initialised */
    strncpy(u->username, name, MAX_USERNAME - 1);
    /* u->password is garbage */
    /* u->profile_data is a dangling / garbage pointer */
}


/* =========================================================
 * Packet Parser – combines multiple CWEs
 * CWE-120, CWE-125, CWE-190, CWE-476, CWE-252
 * ========================================================= */
typedef struct {
    uint16_t  magic;
    uint16_t  version;
    uint32_t  payload_len;
    uint8_t   flags;
    char      payload[1]; /* flexible array via hack */
} NetworkPacket;

int parse_packet(unsigned char *data, int len)
{
    if (len < (int)sizeof(NetworkPacket) - 1) {
        return -1;
    }

    NetworkPacket *pkt = (NetworkPacket *)data;

    /* CWE-190: payload_len from wire, could overflow when added to header size */
    uint32_t total = sizeof(NetworkPacket) + pkt->payload_len; /* VULN */

    char *payload_copy = (char *)malloc(pkt->payload_len + 1); /* CWE-789 */
    /* CWE-252: malloc not checked */

    /* CWE-120: copy payload_len bytes – no check against actual len */
    memcpy(payload_copy, pkt->payload, pkt->payload_len);       /* VULN */
    payload_copy[pkt->payload_len] = '\0';

    /* CWE-134: payload content used as format string */
    printf(payload_copy);   /* VULN */

    free(payload_copy);
    return (int)total;
}


/* =========================================================
 * Report Generator
 * CWE-134, CWE-120, CWE-401
 * ========================================================= */
void generate_report(const char *template_str)
{
    char output[512];
    char *section = NULL;

    /* CWE-120: snprintf OK here but then strcpy without size check below */
    snprintf(output, sizeof(output), "Report: %s", template_str);

    section = (char *)malloc(strlen(template_str) + 64);
    /* CWE-252: malloc not checked */

    sprintf(section, "=== %s ===", template_str); /* CWE-676 again */

    /* CWE-134: section used as format string */
    printf(section);     /* VULN */

    /* CWE-401: section never freed on all paths */
    if (strlen(output) > 500) {
        return;   /* VULN: leaks section */
    }

    free(section);
}


/* =========================================================
 * Checksum with OOB and division pitfalls
 * CWE-125, CWE-369, CWE-195
 * ========================================================= */
int calculate_checksum(int *arr, int count)
{
    long sum = 0;

    /* CWE-125: reads one element past end */
    for (int i = 0; i <= count; i++) {  /* VULN */
        sum += arr[i];
    }

    /* CWE-369 + CWE-195: if count is 0 or negative */
    return (int)(sum / count); /* VULN */
}


/* =========================================================
 * Socket handler
 * CWE-120, CWE-134, CWE-319, CWE-400
 * ========================================================= */
void handle_request(int sock_fd)
{
    char recv_buf[512];
    char resp_buf[256];
    ssize_t n;

    /* CWE-120: recv can fill recv_buf beyond its size if maxlen wrong */
    n = recv(sock_fd, recv_buf, 1024, 0);  /* VULN: 1024 > sizeof(recv_buf) */

    if (n <= 0) return;
    recv_buf[n] = '\0';  /* CWE-120: n could == 512 → off-by-one */

    /* CWE-134: user data used as format string for response */
    snprintf(resp_buf, sizeof(resp_buf), recv_buf, n); /* VULN */

    /* CWE-319: response sent plaintext */
    send(sock_fd, resp_buf, strlen(resp_buf), 0);
}

int start_server(int port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* CWE-252: bind/listen return values not checked */
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));   /* VULN */
    listen(server_fd, 10);                                      /* VULN */

    int client_fd;
    while ((client_fd = accept(server_fd, NULL, NULL)) >= 0) {
        /* CWE-400: no thread pool limit – one thread per connection */
        pthread_t t;
        pthread_create(&t, NULL, (void *(*)(void *))handle_request,
                       (void *)(intptr_t)client_fd); /* CWE-704: cast */
        pthread_detach(t);
    }

    close(server_fd);
    return 0;
}


/* =========================================================
 * Validate index (but with a bug)
 * CWE-125, CWE-193 (off-by-one)
 * ========================================================= */
int validate_index(int idx, int max)
{
    /* CWE-193: off-by-one – allows idx == max, which is OOB */
    if (idx >= 0 && idx <= max) {  /* VULN: should be idx < max */
        return 1;
    }
    return 0;
}

void access_user_array(int idx)
{
    if (validate_index(idx, MAX_USERS)) {
        /* CWE-125: idx == MAX_USERS reads one past end */
        printf("User id: %d\n", g_users[idx].id); /* VULN */
    }
}


/* =========================================================
 * Demo of CWE-330 weak session ID and CWE-200 info leak
 * ========================================================= */
void create_session(int user_id, char *session_id_out)
{
    /* CWE-330: predictable session ID */
    srand(user_id ^ (unsigned int)time(NULL)); /* VULN: low entropy */
    int sid = rand();
    snprintf(session_id_out, 32, "%08x", (unsigned int)sid);

    /* CWE-200: session written to world-readable log */
    log_message("New session: %s for user %d\n", session_id_out, user_id);
}


/* =========================================================
 * CWE-401 + CWE-416 combined scenario
 * ========================================================= */
FileRecord *load_file_record(const char *path)
{
    FileRecord *rec = (FileRecord *)malloc(sizeof(FileRecord));
    if (!rec) return NULL;

    strncpy(rec->filename, path, sizeof(rec->filename) - 1);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        /* CWE-401: rec allocated but not freed on error */
        return NULL;  /* VULN: leaks rec */
    }

    fseek(fp, 0, SEEK_END);
    rec->size = (int)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    rec->data = (char *)malloc(rec->size);
    if (!rec->data) {
        fclose(fp);
        /* CWE-401: rec still leaked */
        return NULL;  /* VULN */
    }

    fread(rec->data, 1, rec->size, fp);
    fclose(fp);
    return rec;
}

void free_file_record(FileRecord *rec)
{
    if (!rec) return;
    free(rec->data);
    free(rec);
    /* Caller may call this twice → CWE-415 */
}

void process_file(const char *path)
{
    FileRecord *rec = load_file_record(path);

    /* CWE-476: no NULL check */
    printf("Loaded %d bytes from %s\n", rec->size, rec->filename); /* VULN */

    free_file_record(rec);
    /* CWE-416: rec used conceptually after free in caller */
}


/* =========================================================
 * Main entry point – ties everything together
 * ========================================================= */
int main(int argc, char *argv[])
{
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char input_buf[MAX_BUFFER];

    /* CWE-665: g_session_token used without initialisation */
    printf("Session: %s\n", g_session_token);  /* VULN */

    /* CWE-242: gets() in main */
    printf("Enter username: ");
    get_username(username);  /* wraps gets() */

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    /* Backdoor check (CWE-506) */
    if (backdoor_check(password)) {
        printf("[BACKDOOR] Root shell granted\n");
        system("/bin/sh");  /* CWE-78 */
        return 0;
    }

    int uid = authenticate_user(username, password);
    if (uid < 0) {
        printf("Authentication failed\n");
        return 1;
    }

    /* CWE-330: weak session */
    char session_id[32];
    create_session(uid, session_id);

    /* Process commands */
    while (1) {
        printf("> ");
        if (!fgets(input_buf, sizeof(input_buf), stdin)) break;
        input_buf[strcspn(input_buf, "\n")] = '\0';

        if (strcmp(input_buf, "quit") == 0) break;

        /* CWE-134: input_buf used as format string */
        printf(input_buf);  /* VULN */

        /* CWE-78: direct system() call with user input */
        if (strncmp(input_buf, "exec ", 5) == 0) {
            system(input_buf + 5);  /* VULN */
        }

        /* CWE-120: unsafe string build */
        build_query("users", input_buf);

        process_user_input(input_buf);
    }

    /* CWE-489: debug info dump */
    if (g_debug_mode) {
        printf("[DEBUG] Exiting. Admin pw: %s\n", g_admin_password); /* VULN: CWE-200 */
        printf("[DEBUG] DB string: %s\n", g_db_conn_string);          /* VULN */
    }

    return 0;
}
/*
 * ============================================================================
 *  vulnerable_realworld.c
 *
 *  SECURITY RESEARCH / SAST BENCHMARK FILE
 *  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 *  DO NOT DEPLOY IN PRODUCTION
 *
 *  Modelled after real-world CVEs and CWE patterns observed in:
 *   - Linux Kernel (CVE-2021-3490, CVE-2022-0847 "Dirty Pipe",
 *                   CVE-2023-0179, CVE-2022-1015)
 *   - OpenSSL (CVE-2022-0778, CVE-2014-0160 "Heartbleed")
 *   - glibc (CVE-2015-7547, CVE-2021-33574)
 *   - sudo (CVE-2021-3156 "Baron Samedit")
 *   - log4shell-style injection (logic port to C)
 *   - libpng (CVE-2018-13785)
 *   - zlib (CVE-2022-37434)
 *   - curl (CVE-2023-38545)
 *   - Samba (CVE-2021-44142)
 *   - F5 BIG-IP (CVE-2022-1388)
 *   - Apache HTTP Server (CVE-2021-41773 path traversal)
 *   - ProFTPD (CWE-134 format string, CVE-2010-4221)
 *   - Qualcomm modem (CVE-2020-11261)
 *   - Wi-Fi stack FragAttacks (CVE-2020-24587)
 *
 *  CWEs demonstrated (50+):
 *   CWE-20, CWE-22, CWE-23, CWE-36, CWE-78, CWE-88, CWE-119,
 *   CWE-120, CWE-121, CWE-122, CWE-123, CWE-124, CWE-125, CWE-126,
 *   CWE-127, CWE-128, CWE-129, CWE-130, CWE-131, CWE-134, CWE-170,
 *   CWE-188, CWE-190, CWE-191, CWE-192, CWE-193, CWE-194, CWE-195,
 *   CWE-197, CWE-200, CWE-201, CWE-209, CWE-242, CWE-252, CWE-253,
 *   CWE-269, CWE-272, CWE-273, CWE-284, CWE-285, CWE-319, CWE-320,
 *   CWE-326, CWE-327, CWE-330, CWE-335, CWE-338, CWE-362, CWE-364,
 *   CWE-369, CWE-377, CWE-390, CWE-391, CWE-400, CWE-401, CWE-404,
 *   CWE-415, CWE-416, CWE-426, CWE-457, CWE-462, CWE-467, CWE-468,
 *   CWE-469, CWE-476, CWE-479, CWE-480, CWE-484, CWE-489, CWE-506,
 *   CWE-561, CWE-563, CWE-570, CWE-571, CWE-587, CWE-590, CWE-606,
 *   CWE-617, CWE-665, CWE-672, CWE-676, CWE-680, CWE-681, CWE-690,
 *   CWE-704, CWE-732, CWE-758, CWE-762, CWE-763, CWE-785, CWE-789,
 *   CWE-805, CWE-822, CWE-824, CWE-825, CWE-843
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <dirent.h>
#include <dlfcn.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <syslog.h>
#include <termios.h>
#include <mqueue.h>
#include <semaphore.h>

/* ============================================================
 *  Constants & Macros
 * ============================================================ */
#define VERSION              "1.3.7"
#define MAX_SESSIONS         512
#define MAX_FILENAME         256
#define MAX_PATH             512
#define MAX_CMD              1024
#define MAX_USERS            1024
#define MAX_PACKET_SIZE      65535
#define HEARTBEAT_MAX        65535   /* CVE-2014-0160 style: no upper bound check */
#define UPLOAD_DIR           "/var/uploads/"
#define LOG_PATH             "/var/log/app.log"
#define TMP_DIR              "/tmp/"
#define CONFIG_FILE          "/etc/app/app.conf"
#define PLUGIN_DIR           "/opt/app/plugins/"
#define SECRET_KEY           "hardcoded_jwt_secret_2024"   /* CWE-321 */
#define DB_PASSWORD          "Pr0d_DB_P@ss!"               /* CWE-259 */
#define ADMIN_BACKDOOR_HASH  "5f4dcc3b5aa765d61d8327deb882cf99" /* CWE-506 */
#define MAX_ALLOC_GUARD      (256 * 1024 * 1024)  /* 256 MB – never enforced */

/* CWE-489: active debug flag left enabled */
static volatile int g_debug = 1;

/* CWE-200: sensitive globals in plaintext */
static char g_db_host[64]   = "10.0.0.5";
static char g_db_user[32]   = "root";
static char g_db_pass[64]   = "Pr0d_DB_P@ss!";
static char g_master_token[128] = "";   /* CWE-665: never initialised */
static char g_enc_key[32]   = { 0xDE, 0xAD, 0xBE, 0xEF }; /* CWE-321 weak key */

/* CWE-362: shared state with no synchronisation */
static int  g_active_sessions = 0;
static int  g_request_counter = 0;

/* Mutex – intentionally not used consistently (CWE-362) */
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int      id;
    char     username[64];
    char     password_hash[64];   /* stored as MD5 – CWE-327 */
    char     email[128];
    int      role;                /* 0=user 1=admin */
    char    *profile_blob;        /* heap pointer */
    uint32_t flags;
    time_t   last_login;
} UserRecord;

typedef struct {
    uint16_t  type;
    uint16_t  length;             /* attacker-controlled */
    uint8_t   data[1];            /* flexible array via pointer cast */
} TLVPacket;

typedef struct {
    char     session_id[64];
    int      user_id;
    uint32_t ip_addr;
    time_t   created_at;
    char    *extra_data;          /* heap, may be freed twice */
    int      valid;
} Session;

typedef struct {
    char  name[128];
    char  value[256];
} ConfigEntry;

typedef struct {
    void  *data;
    size_t len;
    int    type;
    char   tag[16];
} DataChunk;

/* Global session table */
static Session  g_sessions[MAX_SESSIONS];
static UserRecord g_users[MAX_USERS];
static int      g_user_count = 0;


/* ============================================================
 *  Forward declarations
 * ============================================================ */
void        log_event(int level, const char *fmt, ...);
int         parse_http_request(const char *raw, size_t raw_len);
int         authenticate(const char *user, const char *pass);
void        handle_upload(int sock, const char *filename, size_t claimed_size);
int         execute_query(const char *table, const char *condition);
void        process_tlv(uint8_t *buf, uint32_t buf_len);
void        decompress_payload(uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len);
int         load_plugin(const char *name);
void        render_template(const char *tmpl, const char *user_data);
void        admin_exec(int uid, const char *cmd);
int         validate_path(const char *base, const char *user_path, char *out, size_t out_sz);
void        generate_session_id(char *out, size_t len);
void        heartbeat_handler(int sock, const uint8_t *req, uint16_t req_len);
void        process_wifi_frame(uint8_t *frame, size_t frame_len);
void        handle_multipart(int sock, const char *boundary, size_t body_len);
void        cron_runner(const char *schedule_file);
int         parse_config(const char *path, ConfigEntry *entries, int max_entries);
void        handle_dns_response(uint8_t *resp, size_t resp_len);
void        defrag_reassemble(DataChunk *chunks, int count);
void       *worker_thread(void *arg);
void        spawn_worker(int client_fd);
int         check_privilege(int uid, int required_role);
void        audit_log(const char *user, const char *action, const char *resource);
void        handle_rpc(uint8_t *payload, uint32_t len);
void        process_certificate(uint8_t *cert_buf, size_t cert_len);
int         parse_integer_field(const char *str, int base);
void        encode_base64(const uint8_t *in, size_t in_len, char *out);
int         http_chunked_read(int sock, uint8_t **out_buf, size_t *out_len);


/* ============================================================
 *  Section 1: Logging
 *  CWE-134 (Format String), CWE-200 (Info Exposure),
 *  CWE-252 (Unchecked Return), CWE-489 (Debug in Production)
 * ============================================================ */

/*
 * CVE-2010-4221 (ProFTPD): format string via user-controlled log data.
 * log_event() passes fmt directly to vfprintf without sanitisation.
 */
void log_event(int level, const char *fmt, ...)
{
    FILE *fp;
    va_list ap;
    char   tbuf[64];
    time_t now = time(NULL);
    strftime(tbuf, sizeof(tbuf), "%F %T", localtime(&now));

    fp = fopen(LOG_PATH, "a");
    /* CWE-252: fopen return not checked – NULL deref below */

    fprintf(fp, "[%s] [%d] ", tbuf, level);

    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);    /* VULN CWE-134 if fmt contains %n/%s/%p */
    va_end(ap);

    fputc('\n', fp);
    fclose(fp);

    if (g_debug) {
        va_start(ap, fmt);
        /* CWE-134: same format string echoed to stdout unvalidated */
        vprintf(fmt, ap);
        va_end(ap);
        /* CWE-200: dumps internal state */
        printf("\n[DEBUG] db=%s@%s pass=%s master_token=%s\n",
               g_db_user, g_db_host, g_db_pass, g_master_token);
    }
}

/* CWE-209: error message reveals internal path and errno string */
void report_error(const char *operation, const char *path)
{
    /* Sends internal filesystem path + system error to client */
    fprintf(stderr, "ERROR: %s failed on '%s': %s (errno=%d)\n",
            operation, path, strerror(errno), errno);
    syslog(LOG_ERR, "op=%s path=%s err=%s", operation, path, strerror(errno));
}


/* ============================================================
 *  Section 2: Authentication
 *  CWE-259, CWE-285, CWE-307, CWE-326, CWE-327, CWE-330,
 *  CWE-506, CWE-521, CWE-798
 * ============================================================ */

/*
 * Weak MD5 hash comparison – like early phpMyAdmin / older Linux /etc/passwd.
 * CWE-327: use of broken MD5.
 * CWE-285: no account lockout, no rate limit → brute force.
 */
static char *weak_md5(const char *input)
{
    /* Stub: real impl would use OpenSSL MD5 – returning fake for clarity */
    static char fake_hash[33];
    size_t len = strlen(input);
    for (size_t i = 0; i < 32; i++)
        fake_hash[i] = "0123456789abcdef"[(input[i % len] + i) % 16];
    fake_hash[32] = '\0';
    return fake_hash;
}

int authenticate(const char *username, const char *password)
{
    char  hash_input[256];

    /* CWE-120: no bounds check on username + password concat */
    strcpy(hash_input, username);          /* VULN */
    strcat(hash_input, ":");              /* VULN */
    strcat(hash_input, password);         /* VULN */

    char *hashed = weak_md5(hash_input);

    /* CWE-506: backdoor credential bypass */
    if (strcmp(hashed, ADMIN_BACKDOOR_HASH) == 0) {
        log_event(1, "BACKDOOR login by: %s", username);
        return 9999;  /* super-admin UID */
    }

    for (int i = 0; i < g_user_count; i++) {
        /* CWE-285: timing-safe compare NOT used – timing oracle */
        if (strcmp(g_users[i].username, username) == 0 &&
            strcmp(g_users[i].password_hash, hashed) == 0) {
            g_users[i].last_login = time(NULL);
            return g_users[i].id;
        }
    }

    /* CWE-200: leaks whether username exists */
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].username, username) == 0) {
            log_event(2, "Bad password for existing user: %s", username);
            return -2;   /* distinct code → username enumeration */
        }
    }
    return -1;
}

/*
 * CWE-330: session token generated from predictable sources.
 * Mirrors CVE-2023-2243 style weak token generation.
 */
void generate_session_id(char *out, size_t len)
{
    /* CWE-338: srand seeded with time – predictable in 1-second window */
    srand((unsigned int)time(NULL) ^ getpid());

    for (size_t i = 0; i < len - 1; i++) {
        /* CWE-330: only 26^32 keyspace, NOT 256^32 */
        out[i] = 'a' + (rand() % 26);
    }
    out[len - 1] = '\0';
}

/*
 * Privilege check – CWE-285: bypass via negative uid.
 * Mirrors sudo CVE-2019-14287.
 */
int check_privilege(int uid, int required_role)
{
    /* CWE-191: if uid is negative (e.g. -1 passed as "no user"),
     * cast to unsigned may match an entry or bypass check entirely */
    if ((unsigned int)uid == 0xFFFFFFFF)  /* -1 unsigned == root! */
        return 1;

    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].id == uid) {
            /* CWE-285: role value read from user-controlled struct */
            return g_users[i].role >= required_role;
        }
    }
    return 0;
}


/* ============================================================
 *  Section 3: HTTP Request Parser
 *  CWE-20, CWE-22, CWE-119, CWE-120, CWE-125, CWE-190,
 *  CWE-400, CWE-601, CWE-606, CWE-680, CWE-789
 * ============================================================ */

/*
 * CVE-2021-41773 (Apache httpd): path traversal via URL decoding.
 * validate_path() does single-pass decode without loop.
 */
int validate_path(const char *base, const char *user_path, char *out, size_t out_sz)
{
    char decoded[MAX_PATH];
    size_t dlen = 0;
    const char *p = user_path;

    /* CWE-22: single-pass URL decode – double-encoded ../ bypasses check */
    while (*p && dlen < sizeof(decoded) - 1) {
        if (*p == '%' && isxdigit(p[1]) && isxdigit(p[2])) {
            char hex[3] = { p[1], p[2], 0 };
            decoded[dlen++] = (char)strtol(hex, NULL, 16);
            p += 3;
        } else {
            decoded[dlen++] = *p++;
        }
    }
    decoded[dlen] = '\0';

    /* CWE-22: single strstr check – %2e%2e%2f (%2f is /) still passes */
    if (strstr(decoded, "../") != NULL || strstr(decoded, "..\\") != NULL) {
        return -1;
    }

    /* CWE-785 / CWE-120: snprintf into fixed 512-byte out – no realpath */
    snprintf(out, out_sz, "%s%s", base, decoded);   /* VULN: no canonicalize */
    return 0;
}

/*
 * HTTP request parser – models real parser bugs in nginx/Apache.
 * CWE-190: integer overflow in Content-Length header.
 * CWE-125: read past end when header values near buffer edge.
 */
int parse_http_request(const char *raw, size_t raw_len)
{
    char method[16], uri[MAX_PATH], version[16];
    char header_name[128], header_value[1024];
    long content_length = 0;
    const char *cursor = raw;
    const char *end    = raw + raw_len;

    /* CWE-120: sscanf with no width limit – classic stack overflow */
    sscanf(cursor, "%s %s %s", method, uri, version);   /* VULN */

    /* Advance past request line */
    cursor = strchr(cursor, '\n');
    if (!cursor) return -1;
    cursor++;

    /* Parse headers */
    while (cursor < end && *cursor != '\r' && *cursor != '\n') {
        /* CWE-120: header parsing with unchecked sscanf widths */
        sscanf(cursor, "%127[^:]: %1023[^\r\n]", header_name, header_value); /* VULN */

        if (strcasecmp(header_name, "Content-Length") == 0) {
            /* CWE-190: strtol result assigned to long then cast to size_t
             * negative value passes further checks */
            content_length = strtol(header_value, NULL, 10);
            /* CWE-252: no check for LONG_MAX / overflow */
        }

        /* CWE-601: open redirect via Location header – not validated */
        if (strcasecmp(header_name, "X-Redirect-To") == 0) {
            /* Redirect to attacker-controlled URL without scheme check */
            printf("Location: %s\r\n", header_value); /* VULN */
        }

        cursor = strchr(cursor, '\n');
        if (!cursor) break;
        cursor++;
    }

    /* CWE-680: content_length used as malloc size without overflow check */
    if (content_length > 0) {
        /* CWE-789: malloc with unvalidated user-supplied size */
        char *body = (char *)malloc((size_t)content_length + 1);  /* VULN */
        /* CWE-252: malloc not checked */
        if (cursor + content_length > end) {
            /* CWE-125: reading beyond end of raw buffer */
            memcpy(body, cursor, (size_t)content_length); /* VULN: OOB read */
        } else {
            memcpy(body, cursor, (size_t)content_length);
        }
        body[content_length] = '\0';

        /* CWE-401: body not freed on any path */
        /* process body ... */
    }

    return 0;
}

/*
 * CVE-2023-38545 (curl SOCKS5 heap overflow):
 * hostname copied without checking against heap buffer size.
 * CWE-122: heap-based buffer overflow.
 */
int resolve_socks5_hostname(const char *hostname, char *out_buf, size_t out_sz)
{
    size_t hlen = strlen(hostname);

    /* CWE-193: off-by-one – should be hlen >= out_sz */
    if (hlen > out_sz) {      /* VULN: allows hlen == out_sz → no NUL */
        /* Fall back to local resolve */
        strncpy(out_buf, hostname, out_sz);   /* CWE-170: no NUL terminator guarantee */
        return 0;
    }
    /* CWE-122: if hlen == out_sz the NUL write is out-of-bounds */
    memcpy(out_buf, hostname, hlen);
    out_buf[hlen] = '\0';     /* VULN: OOB write when hlen == out_sz */
    return 0;
}


/* ============================================================
 *  Section 4: TLV / Network Packet Processing
 *  CWE-119, CWE-120, CWE-122, CWE-125, CWE-130, CWE-190,
 *  CWE-252, CWE-400, CWE-476, CWE-680, CWE-789
 * ============================================================ */

/*
 * CVE-2014-0160 "Heartbleed" modelled:
 * req_len is attacker-controlled; response copies req_len bytes
 * regardless of the actual data in the request.
 * CWE-125: out-of-bounds read from server memory.
 */
void heartbeat_handler(int sock, const uint8_t *req, uint16_t req_len)
{
    uint8_t *response;
    uint16_t payload_len;

    /* First 2 bytes of req are claimed payload length */
    memcpy(&payload_len, req, sizeof(payload_len));
    /* CWE-20: payload_len not validated against actual req size */

    /* CWE-789: allocate attacker-controlled size up to HEARTBEAT_MAX */
    response = (uint8_t *)malloc(payload_len + 16);  /* VULN */
    if (!response) return;

    /* CWE-125: copy payload_len bytes from req+2 even if req is smaller */
    memcpy(response, req + 2, payload_len);           /* VULN: OOB read leaks heap */
    send(sock, response, payload_len, 0);
    free(response);
}

/*
 * Generic TLV parser – mirrors real protocol stacks (BLE, 802.11, QUIC).
 * CWE-119 / CWE-122: writes past allocated buffer when TLV length > remaining.
 */
void process_tlv(uint8_t *buf, uint32_t buf_len)
{
    uint32_t offset = 0;

    while (offset + 4 <= buf_len) {
        uint16_t type   = *(uint16_t *)(buf + offset);
        uint16_t length = *(uint16_t *)(buf + offset + 2);
        offset += 4;

        if (length == 0) continue;

        /* CWE-789 / CWE-190: attacker-controlled length, no overflow guard */
        uint8_t *value = (uint8_t *)malloc(length);   /* VULN */
        /* CWE-252: malloc not checked */

        /* CWE-125: if length > buf_len - offset, reads past buf */
        memcpy(value, buf + offset, length);           /* VULN */

        /* Dispatch */
        switch (type) {
            case 0x0001:  /* Identity */
                /* CWE-120: strcpy into fixed 64-byte local – length may be bigger */
                {
                    char identity[64];
                    strcpy(identity, (char *)value);   /* VULN */
                    log_event(1, "Identity TLV: %s", identity);
                }
                break;

            case 0x0002:  /* Command string – CWE-78 */
                /* CWE-78: TLV value executed as shell command */
                system((char *)value);                  /* VULN */
                break;

            case 0x0003:  /* Config pointer – CWE-822 */
                {
                    /* CWE-843: type confusion – treats raw bytes as pointer */
                    void *ptr;
                    memcpy(&ptr, value, sizeof(ptr));
                    /* CWE-822: untrusted pointer dereference */
                    memset(ptr, 0, length);             /* VULN */
                }
                break;

            default:
                break;
        }

        free(value);
        offset += length;

        /* CWE-193: off-by-one – offset can wrap if length == UINT16_MAX */
    }
}

/*
 * CVE-2022-37434 (zlib inflateGetHeader):
 * CWE-122: heap overflow when output buffer is smaller than decompressed data.
 * CWE-20: out_len not validated.
 */
void decompress_payload(uint8_t *in, uint32_t in_len,
                        uint8_t *out, uint32_t *out_len)
{
    uint32_t claimed_out_len;

    /* First 4 bytes = claimed uncompressed size */
    memcpy(&claimed_out_len, in, 4);

    /* CWE-789: no cap on claimed_out_len */
    uint8_t *decompressed = (uint8_t *)malloc(claimed_out_len); /* VULN */
    if (!decompressed) return;

    /* Stub decompression – real impl would call zlib */
    uint32_t actual = (in_len - 4 < claimed_out_len) ? in_len - 4 : claimed_out_len;

    /* CWE-122: if out is a fixed buffer and claimed_out_len > sizeof(out) */
    memcpy(out, decompressed, claimed_out_len); /* VULN */
    *out_len = claimed_out_len;

    free(decompressed);
}

/*
 * CVE-2020-24587 (Wi-Fi FragAttacks): fragmented frame reassembly
 * does not verify that all fragments belong to the same MSDU.
 * CWE-364: signal handler race / CWE-345: insufficient verification.
 */
void process_wifi_frame(uint8_t *frame, size_t frame_len)
{
    static uint8_t reassembly_buf[2048];  /* CWE-121: static shared buffer */
    static size_t  reassembly_len = 0;
    static uint8_t last_iv[8];            /* CWE-665: never reset between MSDU */

    uint8_t flags    = frame[0];
    uint8_t frag_num = flags & 0x0F;
    int     more     = (flags >> 4) & 1;
    uint8_t *iv      = frame + 1;
    uint8_t *payload = frame + 9;
    size_t   pay_len = frame_len - 9;

    if (frag_num == 0) {
        reassembly_len = 0;
        memcpy(last_iv, iv, 8);
    }
    /* CWE-345: IV not verified to match first fragment – mixing attack */

    /* CWE-122: no check that reassembly_len + pay_len <= sizeof(reassembly_buf) */
    memcpy(reassembly_buf + reassembly_len, payload, pay_len); /* VULN */
    reassembly_len += pay_len;

    if (!more) {
        /* Process completed frame */
        process_tlv(reassembly_buf, (uint32_t)reassembly_len);
        reassembly_len = 0;
    }
}


/* ============================================================
 *  Section 5: File Operations
 *  CWE-22, CWE-36, CWE-73, CWE-377, CWE-400, CWE-401,
 *  CWE-404, CWE-426, CWE-732, CWE-785
 * ============================================================ */

/*
 * File upload handler – mirrors Samba CVE-2021-44142 / PHP file upload bugs.
 * CWE-22: user-supplied filename used to construct path.
 * CWE-400: claimed_size not capped.
 */
void handle_upload(int sock, const char *filename, size_t claimed_size)
{
    char    path[MAX_PATH];
    uint8_t *buf;
    ssize_t  received;
    int      fd;

    /* CWE-22: filename not sanitised – "../../../etc/cron.d/backdoor" works */
    snprintf(path, sizeof(path), "%s%s", UPLOAD_DIR, filename);  /* VULN */

    /* CWE-377: predictable temp path, O_EXCL not used */
    char tmp_path[64];
    sprintf(tmp_path, "/tmp/upload_%d", getpid());               /* VULN */
    fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return;

    /* CWE-789 / CWE-400: malloc with attacker-supplied size, no cap */
    buf = (uint8_t *)malloc(claimed_size);    /* VULN */
    if (!buf) { close(fd); return; }

    /* CWE-400: reading up to claimed_size from socket – no timeout */
    received = recv(sock, buf, claimed_size, MSG_WAITALL);
    if (received > 0) {
        /* CWE-732: file written with world-readable perms */
        write(fd, buf, (size_t)received);
    }

    close(fd);

    /* CWE-426: rename uses non-atomic user-supplied path */
    rename(tmp_path, path);                   /* VULN: TOCTOU between validate and rename */
    free(buf);
}

/*
 * CWE-362 / CWE-367 (TOCTOU): stat() then open() – attacker can swap symlink.
 * Mirrors CVE-2022-27626 (runc) and Linux tmp race patterns.
 */
int safe_open_config(const char *path)
{
    struct stat st;

    /* CWE-362: check */
    if (stat(path, &st) != 0)      return -1;
    if (!S_ISREG(st.st_mode))      return -1;
    if (st.st_size > 1024 * 1024)  return -1;

    /* CWE-362: use – window between stat and open allows symlink swap */
    int fd = open(path, O_RDONLY); /* VULN */
    return fd;
}

/*
 * Config file parser – CWE-119 / CWE-120 / CWE-134.
 */
int parse_config(const char *path, ConfigEntry *entries, int max_entries)
{
    char  line[512];
    char  key[256], val[256];
    int   count = 0;
    FILE *fp;

    fp = fopen(path, "r");
    if (!fp) return -1;

    while (fgets(line, sizeof(line), fp) && count < max_entries) {
        if (line[0] == '#' || line[0] == '\n') continue;

        /* CWE-120: sscanf with no width for key/val – overflow if line is crafted */
        if (sscanf(line, "%[^=]=%[^\n]", key, val) == 2) {  /* VULN */
            /* CWE-120: strncpy without NUL guarantee */
            strncpy(entries[count].name,  key, 127);
            strncpy(entries[count].value, val, 255);
            count++;
        }
    }

    fclose(fp);

    /* CWE-134: key used as format string in log */
    if (g_debug && count > 0) {
        log_event(0, entries[0].name);   /* VULN CWE-134 */
    }

    return count;
}

/*
 * Directory listing – CWE-22: unsanitised user path traversal.
 */
void list_user_files(const char *base_dir, const char *user_subdir)
{
    char full_path[MAX_PATH];
    DIR *dp;
    struct dirent *ent;

    /* CWE-22: user_subdir not validated → ../../etc */
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, user_subdir); /* VULN */

    dp = opendir(full_path);
    if (!dp) {
        report_error("opendir", full_path);  /* CWE-209: leaks internal path */
        return;
    }

    while ((ent = readdir(dp)) != NULL) {
        /* CWE-134: filename from disk fed directly to printf */
        printf(ent->d_name);   /* VULN CWE-134 */
        putchar('\n');
    }
    closedir(dp);
}


/* ============================================================
 *  Section 6: Memory Management
 *  CWE-122, CWE-190, CWE-401, CWE-415, CWE-416, CWE-590,
 *  CWE-672, CWE-762, CWE-763, CWE-824, CWE-825
 * ============================================================ */

/*
 * Session creation / destruction.
 * CWE-415: double free on session extra_data.
 * CWE-416: use after free on session struct.
 */
Session *create_session(int user_id, uint32_t ip)
{
    if (g_active_sessions >= MAX_SESSIONS) return NULL;

    /* CWE-362: g_active_sessions read/written without lock */
    int idx = g_active_sessions++;

    Session *s = &g_sessions[idx];
    generate_session_id(s->session_id, sizeof(s->session_id));
    s->user_id    = user_id;
    s->ip_addr    = ip;
    s->created_at = time(NULL);
    s->valid      = 1;

    /* CWE-401: if malloc fails, extra_data is NULL but valid=1 still set */
    s->extra_data = (char *)malloc(256);

    return s;
}

void destroy_session(Session *s)
{
    if (!s) return;
    s->valid = 0;

    free(s->extra_data);     /* first free */
    /* ... some other code ... */
    free(s->extra_data);     /* CWE-415: double free */ /* VULN */

    /* CWE-672: s still reachable via g_sessions[idx] after free of members */
}

/*
 * User profile – heap overflow via integer overflow in size computation.
 * Mirrors CVE-2021-3490 (eBPF verifier int overflow) conceptually.
 * CWE-190 + CWE-122.
 */
char *allocate_profile(uint32_t num_fields, uint32_t field_size)
{
    /* CWE-190: multiplication overflow – 0x10000 * 0x10000 = 0 */
    uint32_t total = num_fields * field_size;   /* VULN */

    /* CWE-789: total may be 0 or tiny due to overflow → heap overflow below */
    char *profile = (char *)malloc(total);
    if (!profile) return NULL;

    /* Caller will write num_fields * field_size bytes, overflowing profile */
    return profile;
}

/*
 * CWE-416: use-after-free in user record management.
 * Similar to Linux kernel UAF bugs (CVE-2022-0847 "Dirty Pipe" used pipe
 * internals; here we model a simpler user-space equivalent).
 */
static char *g_cached_username = NULL;

void cache_username(const char *name)
{
    free(g_cached_username);   /* OK */
    g_cached_username = strdup(name);
}

void invalidate_cache(void)
{
    free(g_cached_username);
    g_cached_username = NULL;  /* dangling in concurrent path */
}

void use_cached_username(void)
{
    /* CWE-416: another thread may have called invalidate_cache() */
    /* CWE-362: no lock around access */
    printf("User: %s\n", g_cached_username);   /* VULN */
}

/*
 * CWE-590: freeing stack-allocated memory.
 * CWE-762: mismatched new/free (conceptual – in C: stack vs heap).
 */
void process_local_buffer(int use_stack)
{
    char  stack_buf[128] = "stack data";
    char *heap_buf       = (char *)malloc(128);
    char *target;

    if (use_stack)
        target = stack_buf;
    else
        target = heap_buf;

    strncpy(target, "processed", 9);

    /* CWE-590: if use_stack==1, freeing stack memory → UB */
    free(target);   /* VULN */

    /* CWE-401: heap_buf leaks when use_stack==0 and target==heap_buf */
}

/*
 * CWE-824 / CWE-825: uninitialized / expired pointer access.
 */
char *get_stale_pointer(void)
{
    char *p = (char *)malloc(64);
    strcpy(p, "temporary");
    free(p);
    return p;     /* CWE-825: returning freed (expired) pointer */
}

void use_stale_pointer(void)
{
    char *ptr = get_stale_pointer();
    /* CWE-416 / CWE-825 */
    printf("%s\n", ptr);   /* VULN: UAF */
    free(ptr);             /* CWE-415: double free */
}

/*
 * realloc pitfall – CWE-401: original pointer leaked if realloc fails.
 */
int grow_buffer(char **buf, size_t *buf_sz, size_t needed)
{
    if (needed <= *buf_sz) return 0;

    /* CWE-401: if realloc returns NULL, *buf is overwritten with NULL
     * but the original allocation is lost */
    *buf = (char *)realloc(*buf, needed);   /* VULN */
    if (!*buf) return -1;

    *buf_sz = needed;
    return 0;
}


/* ============================================================
 *  Section 7: Integer Vulnerabilities
 *  CWE-128, CWE-129, CWE-190, CWE-191, CWE-192, CWE-193,
 *  CWE-194, CWE-195, CWE-197, CWE-369, CWE-680, CWE-681
 * ============================================================ */

/*
 * CWE-680: integer overflow to buffer overflow.
 * Mirrors libpng CVE-2018-13785: width * height * bpp overflow.
 */
void *alloc_image_buffer(uint32_t width, uint32_t height, uint32_t bpp)
{
    /* CWE-190: all three are attacker-controlled – overflow to small alloc */
    uint32_t row_bytes = width * bpp;            /* VULN */
    uint32_t total     = row_bytes * height;     /* VULN */
    /* total can be 0 if overflow wraps */

    void *buf = malloc(total);
    if (!buf) return NULL;

    /* Caller fills width * height * bpp bytes → heap overflow */
    return buf;
}

/*
 * Signed / unsigned confusion – CVE-2021-3156 (sudo) used a similar
 * signed-length passed to realloc.
 * CWE-195: signed-to-unsigned conversion.
 */
void sudoers_style_overflow(int argc, char **argv)
{
    char  command[MAX_CMD];
    int   len = 0;

    for (int i = 1; i < argc; i++) {
        int arg_len = (int)strlen(argv[i]);

        /* CWE-190: len + arg_len can overflow if many large args */
        len += arg_len + 1;   /* VULN */
    }

    /* CWE-195: len is signed; if overflow → negative → huge size_t */
    char *buf = (char *)malloc((size_t)len);   /* VULN */
    if (!buf) return;

    buf[0] = '\0';
    for (int i = 1; i < argc; i++) {
        /* CWE-120: strcat without bounds */
        strcat(buf, argv[i]);   /* VULN */
        strcat(buf, " ");
    }

    free(buf);
}

/*
 * CWE-369: divide by zero via user-supplied denominator.
 * CWE-191: integer underflow.
 */
int compute_rate(int events, int seconds)
{
    /* CWE-369: no guard for seconds == 0 */
    return events / seconds;   /* VULN */
}

long safe_subtract(long a, long b)
{
    /* CWE-191: result < LONG_MIN not checked */
    return a - b;   /* VULN: if b > LONG_MAX − a, undefined behaviour */
}

/*
 * CWE-193: off-by-one in loop bound (classic fencepost).
 */
int find_delimiter(const char *str, size_t len)
{
    /* CWE-193: i <= len reads one past end */
    for (size_t i = 0; i <= len; i++) {   /* VULN */
        if (str[i] == '\0' || str[i] == '\n')
            return (int)i;
    }
    return -1;
}

/*
 * CWE-197: numeric truncation.
 * CWE-194: unexpected sign extension.
 */
void numeric_truncation_demo(void)
{
    long long big = 0xDEADBEEFCAFEBABELL;
    int       med = (int)big;               /* CWE-197: truncated */
    short     sm  = (short)big;             /* CWE-197: truncated further */
    char      tiny = (char)big;            /* CWE-197 */

    /* CWE-194: char (signed) extended to int – 0xFF becomes -1 */
    unsigned char uc = 0xFF;
    int           si = uc;   /* safe, but: */
    signed char   sc = (signed char)uc;   /* sc == -1 */
    int           extended = sc;           /* CWE-194: -1 propagates */

    (void)med; (void)sm; (void)tiny; (void)si; (void)extended;
}

/*
 * CWE-129: array index not validated.
 */
char g_lookup_table[256] = {0};

char table_lookup(int index)
{
    /* CWE-129: index from user, no range check */
    return g_lookup_table[index];   /* VULN: OOB if index < 0 or > 255 */
}


/* ============================================================
 *  Section 8: Race Conditions & Concurrency
 *  CWE-362, CWE-364, CWE-366, CWE-367, CWE-479, CWE-820
 * ============================================================ */

static int g_refcount = 0;

/*
 * CWE-366: race on refcount without atomic operation.
 * Mirrors Linux kernel UAF races (CVE-2022-1015).
 */
void refcount_inc(void)
{
    /* CWE-366: non-atomic read-modify-write */
    g_refcount++;   /* VULN: two threads can read same value simultaneously */
}

void refcount_dec(void)
{
    /* CWE-415: if refcount reaches 0 from two threads simultaneously,
     * the resource is freed twice */
    if (--g_refcount == 0) {   /* VULN */
        free(g_cached_username);
        g_cached_username = NULL;
    }
}

/* Worker thread – CWE-362: accesses global state without lock */
void *worker_thread(void *arg)
{
    int client_fd = (int)(intptr_t)arg;
    char buf[1024];
    ssize_t n;

    /* CWE-362: g_request_counter incremented without lock */
    g_request_counter++;   /* VULN */

    n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) goto cleanup;
    buf[n] = '\0';

    /* CWE-134: buf from network used as format string */
    log_event(1, buf);    /* VULN */

    parse_http_request(buf, (size_t)n);

cleanup:
    close(client_fd);
    return NULL;
}

void spawn_worker(int client_fd)
{
    pthread_t t;
    /* CWE-400: no limit on thread count → resource exhaustion */
    pthread_create(&t, NULL, worker_thread, (void *)(intptr_t)client_fd); /* VULN */
    pthread_detach(t);
}

/*
 * CWE-479: signal handler uses non-async-signal-safe functions.
 * Mirrors CVE-2023-0179 (Netfilter async signal race).
 */
static volatile sig_atomic_t g_got_signal = 0;

void signal_handler(int sig)
{
    /* CWE-479: malloc, printf, log_event are NOT async-signal-safe */
    char *buf = (char *)malloc(128);   /* VULN */
    if (buf) {
        snprintf(buf, 128, "Signal %d received\n", sig);
        printf("%s", buf);             /* VULN */
        log_event(1, buf);             /* VULN */
        free(buf);
    }
    g_got_signal = 1;
}

void setup_signals(void)
{
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);  /* CWE-617: handling SIGSEGV and continuing */
}


/* ============================================================
 *  Section 9: Injection Vulnerabilities
 *  CWE-78, CWE-88, CWE-89, CWE-94, CWE-643
 * ============================================================ */

/*
 * SQL injection – CWE-89.
 * Mirrors classic LAMP-stack injection.
 */
int execute_query(const char *table, const char *condition)
{
    char query[1024];

    /* CWE-89: condition is user-supplied, no parameterisation */
    /* CWE-120: sprintf without bounds → stack overflow if inputs large */
    sprintf(query, "SELECT * FROM %s WHERE %s;", table, condition);  /* VULN */

    if (g_debug)
        printf("[SQL] %s\n", query);   /* CWE-200: query leaked to debug */

    /* Simulate execution */
    return 0;
}

/*
 * OS command injection – CWE-78.
 * Mirrors CVE-2021-41773 command exec via RewriteRule.
 */
void admin_exec(int uid, const char *cmd)
{
    char full_cmd[MAX_CMD];

    if (!check_privilege(uid, 1)) {
        /* CWE-285: privilege check returns but code falls through */
    }

    /* CWE-78: cmd directly inserted into shell command */
    snprintf(full_cmd, sizeof(full_cmd), "sudo -u service %s", cmd);  /* VULN */
    system(full_cmd);   /* VULN */
}

/*
 * CWE-88: argument injection via unescaped curl invocation.
 * Mirrors CVE-2021-22945 (curl).
 */
void fetch_url(const char *url)
{
    char cmd[512];
    /* CWE-88: url could contain "--output /etc/cron.d/backdoor" */
    snprintf(cmd, sizeof(cmd), "curl -s '%s'", url);   /* VULN */
    system(cmd);   /* VULN */
}

/*
 * Template injection – CWE-94 / Server-Side Template Injection.
 * CWE-134: user_data used directly as format string.
 */
void render_template(const char *tmpl, const char *user_data)
{
    char output[4096];
    char combined[4096];

    /* CWE-120: snprintf but tmpl + user_data may exceed 4096 */
    snprintf(combined, sizeof(combined), tmpl, user_data);   /* VULN CWE-134 if tmpl has % */

    /* CWE-134: output used as format string in printf */
    printf(combined);   /* VULN */
}

/*
 * LDAP injection stub – CWE-90.
 */
int ldap_authenticate(const char *user, const char *pass)
{
    char filter[256];
    /* CWE-90: user and pass not escaped → injection via ) characters */
    snprintf(filter, sizeof(filter),
             "(&(uid=%s)(userPassword=%s))", user, pass);  /* VULN */
    /* Simulate ldap_search(conn, base, LDAP_SCOPE_SUBTREE, filter, ...) */
    return 0;
}


/* ============================================================
 *  Section 10: Cryptography Failures
 *  CWE-310, CWE-319, CWE-320, CWE-326, CWE-327, CWE-330,
 *  CWE-335, CWE-338, CWE-347
 * ============================================================ */

/*
 * CWE-327: RC4 / XOR "encryption" – trivially reversible.
 * CWE-326: single-byte key.
 */
void xor_encrypt(const uint8_t *in, size_t len, uint8_t *out)
{
    /* CWE-326: fixed single-byte key from hardcoded constant */
    uint8_t key = g_enc_key[0];   /* CWE-798 */
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ key;     /* VULN */
}

/*
 * JWT "verification" – CWE-347: algorithm confusion (alg:none).
 * Mirrors real JWT library bugs (CVE-2022-21449 Java, others).
 */
int verify_jwt(const char *token)
{
    char header_b64[256], payload_b64[256], sig_b64[256];
    char alg[32];

    /* CWE-120: sscanf without width limits */
    sscanf(token, "%[^.].%[^.].%s", header_b64, payload_b64, sig_b64); /* VULN */

    /* Fake decode: pretend we decoded header and got algorithm field */
    strcpy(alg, "HS256");   /* in real bug, attacker sets alg="none" */

    /* CWE-347: if alg=="none" we skip signature verification */
    if (strcmp(alg, "none") == 0) {
        return 1;   /* VULN: accepts unsigned token */
    }

    /* CWE-326: compare with fixed secret using strcmp – timing oracle */
    char expected_sig[256] = {0};
    xor_encrypt((const uint8_t *)payload_b64, strlen(payload_b64),
                (uint8_t *)expected_sig);

    /* CWE-285: strcmp not timing-safe */
    return strcmp(sig_b64, expected_sig) == 0;   /* VULN */
}

/*
 * CWE-335: seed reuse across processes via fork.
 * CWE-338: predictable key generation.
 */
void generate_encryption_key(uint8_t *key_out, size_t key_len)
{
    /* CWE-335: if this process was forked, srand state is duplicated */
    srand((unsigned int)time(NULL));   /* CWE-338 */

    for (size_t i = 0; i < key_len; i++) {
        key_out[i] = (uint8_t)(rand() % 256);   /* VULN: low entropy */
    }
}

/*
 * CWE-319: sending credentials over plaintext socket.
 * Mirrors POP3/SMTP plaintext auth bugs.
 */
void send_auth_plaintext(int sock, const char *user, const char *pass)
{
    char buf[512];
    /* CWE-319: credentials in cleartext */
    snprintf(buf, sizeof(buf), "AUTH PLAIN %s %s\r\n", user, pass);
    send(sock, buf, strlen(buf), 0);   /* VULN: no TLS */
}


/* ============================================================
 *  Section 11: Privilege & Access Control
 *  CWE-269, CWE-272, CWE-273, CWE-284, CWE-285, CWE-732
 * ============================================================ */

/*
 * CWE-269: unconditional privilege escalation.
 * CWE-273: setuid return value not checked.
 */
void drop_privileges(void)
{
    /* CWE-273: if setgid/setuid fail (e.g. process already root), we continue */
    setgid(65534);   /* VULN: return value ignored */
    setuid(65534);   /* VULN: return value ignored */
    /* If either fails, process still runs as root */
}

void elevate_for_operation(void)
{
    /* CWE-269: blanket elevation with no authorization gate */
    setuid(0);   /* VULN */
    setgid(0);   /* VULN */
}

/*
 * CWE-732: creating files/dirs with world-writable permissions.
 * Mirrors OpenSSH CVE-2023-38408 style permission issues.
 */
void create_work_directory(const char *name)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "/var/run/app/%s", name);
    /* CWE-732: 0777 allows any user to write */
    mkdir(path, 0777);                           /* VULN */
    /* CWE-252: mkdir return not checked */

    /* CWE-732: log file world-writable */
    int fd = open(LOG_PATH, O_CREAT | O_WRONLY | O_APPEND, 0666);  /* VULN */
    if (fd >= 0) close(fd);
}

/*
 * CWE-272: least privilege violation – full privileges retained.
 * Mirrors CVE-2023-26604 (systemd) – service kept root unnecessarily.
 */
void start_network_listener(int port)
{
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* CWE-252: bind / listen return values unchecked */
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));   /* VULN */
    listen(sock, 128);                                     /* VULN */

    /* CWE-272: should drop privileges after bind, but doesn't */
    /* drop_privileges();  -- commented out / forgotten */

    int client;
    while ((client = accept(sock, NULL, NULL)) >= 0) {
        /* CWE-400: unbounded thread creation */
        spawn_worker(client);   /* VULN */
    }
    close(sock);
}


/* ============================================================
 *  Section 12: DNS & RPC Parsing
 *  CWE-119, CWE-120, CWE-130, CWE-190, CWE-400, CWE-476
 * ============================================================ */

/*
 * DNS response parser – mirrors glibc CVE-2015-7547.
 * CWE-122: heap overflow when copying DNS answer into fixed buffer.
 */
void handle_dns_response(uint8_t *resp, size_t resp_len)
{
    uint8_t  *p   = resp;
    uint8_t  *end = resp + resp_len;
    char      name[256];
    uint16_t  rdlength;
    char      rdata[64];    /* CWE-131: buffer too small for full RDATA */

    /* Skip header (12 bytes) */
    if (resp_len < 12) return;
    p += 12;

    /* Parse QNAME (label encoding) */
    int nlen = 0;
    while (p < end && *p) {
        uint8_t label_len = *p++;
        if (p + label_len > end) return;
        /* CWE-120: no check that nlen + label_len < sizeof(name) */
        memcpy(name + nlen, p, label_len);   /* VULN */
        nlen += label_len;
        name[nlen++] = '.';
        p += label_len;
    }
    name[nlen] = '\0';
    p++;   /* skip root label */

    p += 4;  /* skip QTYPE / QCLASS */

    /* Parse answer RDATA */
    if (p + 10 > end) return;
    p += 8;  /* skip NAME, TYPE, CLASS, TTL */

    memcpy(&rdlength, p, 2);
    rdlength = ntohs(rdlength);
    p += 2;

    /* CWE-122: rdlength not bounded to sizeof(rdata) */
    memcpy(rdata, p, rdlength);   /* VULN: heap / stack overflow */
    rdata[rdlength] = '\0';       /* VULN: OOB write if rdlength == 64 */

    printf("Resolved %s -> %s\n", name, rdata);
}

/*
 * RPC handler – mirrors Sun RPC / ONCRPC parsing bugs.
 * CWE-130 / CWE-190: improper calc of buffer size.
 */
void handle_rpc(uint8_t *payload, uint32_t len)
{
    uint32_t proc, xid, data_len;

    if (len < 12) return;
    memcpy(&xid,      payload,     4);
    memcpy(&proc,     payload + 4, 4);
    memcpy(&data_len, payload + 8, 4);

    xid      = ntohl(xid);
    proc     = ntohl(proc);
    data_len = ntohl(data_len);

    /* CWE-130: data_len not validated; may exceed actual payload */
    /* CWE-789: malloc size from wire */
    uint8_t *data = (uint8_t *)malloc(data_len);   /* VULN */
    /* CWE-252: not checked */

    /* CWE-125: copies data_len bytes even if payload + 12 + data_len > end */
    memcpy(data, payload + 12, data_len);           /* VULN */

    switch (proc) {
        case 1:
            /* CWE-78: RPC payload used as command */
            system((char *)data);   /* VULN */
            break;
        case 2:
            /* CWE-134: payload used as format string */
            printf((char *)data);   /* VULN */
            break;
        default:
            break;
    }

    free(data);
}


/* ============================================================
 *  Section 13: Certificate & ASN.1 Parsing
 *  CWE-119, CWE-190, CWE-400, CWE-476, CWE-680
 * ============================================================ */

/*
 * CVE-2022-0778 (OpenSSL infinite loop in BN_mod_sqrt).
 * Conceptual port: loop without convergence check.
 * CWE-400: uncontrolled resource consumption.
 */
uint64_t modular_sqrt(uint64_t n, uint64_t p)
{
    uint64_t x = n % p;

    /* CWE-400: if p==0 or p is crafted, this may not converge */
    while (x * x % p != n % p) {   /* VULN: infinite loop possible */
        x++;
        if (x == 0) break;  /* wrap – but doesn't fix infinite loop */
    }
    return x;
}

/*
 * ASN.1 DER length parsing – mirrors multiple TLS library CVEs.
 * CWE-190: multi-byte length overflow.
 */
uint32_t parse_asn1_length(const uint8_t *p, const uint8_t *end,
                            const uint8_t **next)
{
    if (p >= end) return 0;

    uint8_t first = *p++;

    if (!(first & 0x80)) {
        *next = p;
        return first;
    }

    int num_bytes = first & 0x7F;
    if (num_bytes > 4) return 0;  /* reject >4 byte lengths */

    uint32_t length = 0;
    for (int i = 0; i < num_bytes; i++) {
        if (p >= end) return 0;
        /* CWE-190: shift overflow if length already has high bits set */
        length = (length << 8) | *p++;   /* VULN: shift UB if length > 2^24 */
    }

    *next = p;
    return length;
}

void process_certificate(uint8_t *cert_buf, size_t cert_len)
{
    const uint8_t *p    = cert_buf;
    const uint8_t *end  = cert_buf + cert_len;
    const uint8_t *next;

    /* Skip outer SEQUENCE tag */
    if (*p++ != 0x30) return;
    uint32_t outer_len = parse_asn1_length(p, end, &next);
    p = next;

    /* CWE-190: outer_len + (p - cert_buf) may overflow */
    if (p + outer_len > end) return;

    /* Inner SEQUENCE – subject field */
    if (*p++ != 0x30) return;
    uint32_t subj_len = parse_asn1_length(p, end, &next);
    p = next;

    /* CWE-789: subj_len from wire, no cap */
    char *subject = (char *)malloc(subj_len + 1);   /* VULN */
    if (!subject) return;

    /* CWE-125: if p + subj_len > end, reads past buffer */
    memcpy(subject, p, subj_len);   /* VULN */
    subject[subj_len] = '\0';

    log_event(1, "Certificate subject: %s", subject);
    free(subject);
}


/* ============================================================
 *  Section 14: HTTP Chunked Transfer & Multipart
 *  CWE-119, CWE-120, CWE-190, CWE-400, CWE-401
 * ============================================================ */

/*
 * Chunked transfer encoding – mirrors real HTTP server parser bugs.
 * CWE-190: chunk size parsed as hex, can overflow size_t.
 */
int http_chunked_read(int sock, uint8_t **out_buf, size_t *out_len)
{
    uint8_t *body     = NULL;
    size_t   body_len = 0;
    char     size_line[32];

    while (1) {
        /* Read chunk size line */
        ssize_t n = recv(sock, size_line, sizeof(size_line) - 1, 0);
        if (n <= 0) break;
        size_line[n] = '\0';

        /* CWE-190: strtoul can return ULONG_MAX on overflow → tiny alloc */
        size_t chunk_sz = strtoul(size_line, NULL, 16);   /* VULN: no overflow check */
        if (chunk_sz == 0) break;

        /* CWE-190: body_len + chunk_sz can overflow */
        size_t new_len = body_len + chunk_sz;   /* VULN */

        /* CWE-401: if realloc fails, body is leaked */
        uint8_t *new_body = (uint8_t *)realloc(body, new_len);   /* VULN */
        if (!new_body) break;
        body = new_body;

        n = recv(sock, body + body_len, chunk_sz, MSG_WAITALL);
        if (n <= 0) break;
        body_len += (size_t)n;
    }

    *out_buf = body;
    *out_len  = body_len;
    return 0;
}

/*
 * Multipart form-data parser – CVE-2017-5638 (Apache Struts) style.
 * CWE-120: boundary not bounded; body_len not validated.
 */
void handle_multipart(int sock, const char *boundary, size_t body_len)
{
    char   part_header[1024];
    char   filename[MAX_FILENAME];
    char   content_type[128];
    char   upload_path[MAX_PATH];
    uint8_t *data;
    ssize_t  n;

    /* CWE-789 / CWE-400: malloc with full body_len, no cap */
    data = (uint8_t *)malloc(body_len);   /* VULN */
    if (!data) return;

    n = recv(sock, data, body_len, MSG_WAITALL);
    if (n <= 0) { free(data); return; }

    /* Parse part headers (simplified) */
    /* CWE-120: filename from headers copied without bound check */
    sscanf(part_header,
           "Content-Disposition: form-data; name=\"file\"; filename=\"%255[^\"]\"",
           filename);   /* VULN: 255 may not protect if sscanf output larger */

    /* CWE-22: filename not sanitised */
    snprintf(upload_path, sizeof(upload_path), "%s%s", UPLOAD_DIR, filename); /* VULN */

    int fd = open(upload_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, data, (size_t)n);
        close(fd);
    }

    free(data);
}


/* ============================================================
 *  Section 15: Plugin / Dynamic Loading
 *  CWE-114, CWE-426, CWE-427, CWE-506
 * ============================================================ */

/*
 * CWE-426 / CWE-427: dlopen with untrusted search path.
 * Mirrors CVE-2022-24826 (actions/checkout) concept in C.
 */
int load_plugin(const char *name)
{
    char lib_path[512];
    void *handle;
    void (*init_fn)(void);

    /* CWE-427: name could be an absolute path or relative – attacker-controlled */
    snprintf(lib_path, sizeof(lib_path), "%s%s.so", PLUGIN_DIR, name);  /* VULN */

    /* CWE-426: RTLD_GLOBAL exposes symbols to other loaded libs */
    handle = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);  /* VULN */
    if (!handle) {
        /* CWE-209: dlerror() leaks internal path */
        fprintf(stderr, "Plugin load failed: %s\n", dlerror());
        return -1;
    }

    init_fn = (void (*)(void))dlsym(handle, "plugin_init");
    /* CWE-476: init_fn may be NULL if symbol not found */
    init_fn();   /* VULN: NULL function pointer call */

    return 0;
}

/*
 * Cron-style scheduler – CWE-78 via schedule file.
 */
void cron_runner(const char *schedule_file)
{
    FILE  *fp;
    char   line[512];
    char   cmd[MAX_CMD];

    fp = fopen(schedule_file, "r");
    /* CWE-252: fopen not checked */

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#') continue;

        /* CWE-120: sscanf with no width – schedule line overflow */
        sscanf(line, "%*s %*s %*s %*s %*s %[^\n]", cmd);   /* VULN */

        /* CWE-78: cmd from file executed directly */
        system(cmd);   /* VULN */
    }

    fclose(fp);
}


/* ============================================================
 *  Section 16: Miscellaneous Real-World Patterns
 *  CWE-170, CWE-188, CWE-480, CWE-484, CWE-561, CWE-563,
 *  CWE-570, CWE-571, CWE-587, CWE-606, CWE-617, CWE-672
 * ============================================================ */

/*
 * CWE-170: NUL terminator assumption violated by strncpy.
 * Mirrors OpenSSH banner parsing pattern.
 */
void parse_banner(const char *data, size_t len)
{
    char banner[64];
    char version[32];

    /* CWE-170: strncpy does NOT NUL-terminate if src >= dst size */
    strncpy(banner, data, sizeof(banner));   /* VULN: no NUL if len >= 64 */

    /* version is now potentially unterminated; printf reads past buffer */
    sscanf(banner, "APP-%31s", version);
    printf("Banner version: %s\n", version);   /* VULN */
}

/*
 * CWE-480: wrong operator – = instead of ==.
 */
int check_admin_flag(int flags)
{
    int is_admin;
    /* CWE-480: assignment instead of comparison – always sets is_admin=1 */
    if ((is_admin = (flags & 0x01))) {   /* VULN: intended == 1 comparison */
        return 1;
    }
    return 0;
}

/*
 * CWE-484: omitted break in switch → fall-through.
 * Mirrors Heartbleed-era OpenSSL switch bugs.
 */
const char *get_hash_name(int alg_id)
{
    switch (alg_id) {
        case 1:
            return "MD5";   /* CWE-484: missing break – falls to case 2 */
        case 2:
            return "SHA1";  /* also weak */
        case 3:
            return "SHA256";
        default:
            return "UNKNOWN";
    }
}

/*
 * CWE-606: unchecked loop condition – loop may never terminate.
 */
int find_pattern(const char *buf, size_t buf_len, uint8_t pattern)
{
    size_t i = 0;
    /* CWE-606: buf_len could be 0; i-- wraps to SIZE_MAX → infinite */
    while (i < buf_len && buf[i] != (char)pattern) {
        i++;
    }
    /* CWE-606: i == buf_len is not checked before return */
    return (int)i;
}

/*
 * CWE-563: variable assigned but never used.
 * CWE-561: dead code.
 */
int compute_checksum(const uint8_t *data, size_t len)
{
    uint32_t crc  = 0xFFFFFFFF;
    uint32_t temp = 0;   /* CWE-563: temp set but never used */
    size_t   pad  = 0;   /* CWE-563 */

    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    /* CWE-561: dead code – return below is unreachable after this */
    if (0) {
        crc = 0;   /* dead */
    }

    return (int)(crc ^ 0xFFFFFFFF);
}

/*
 * CWE-570 / CWE-571: always-false / always-true conditions.
 */
void always_condition_demo(int x)
{
    /* CWE-571: always true */
    if (sizeof(int) >= 0) {      /* VULN: sizeof returns size_t ≥ 0 always */
        printf("This always runs\n");
    }

    /* CWE-570: always false */
    unsigned int u = (unsigned int)x;
    if (u < 0) {                 /* VULN: unsigned < 0 is always false */
        printf("Never executes\n");   /* CWE-561 */
    }
}

/*
 * CWE-587: assignment of fixed hardware address.
 */
void mmio_access(void)
{
    /* CWE-587: directly dereferencing magic address – UB on modern OS */
    volatile uint32_t *reg = (volatile uint32_t *)0xFED00000UL;  /* VULN */
    *reg = 0xDEADBEEF;
}

/*
 * CWE-617: reachable assertion – attacker can trigger assert() via input.
 */
void process_message_length(size_t msg_len)
{
    /* CWE-617: assert with user-controlled value – abort() if msg_len==0 */
    assert(msg_len > 0);   /* VULN: should be if-check with graceful return */
    assert(msg_len < MAX_PACKET_SIZE);
}

/*
 * CWE-672: operation on resource after expiration.
 * File descriptor used after being closed.
 */
void fd_use_after_close(void)
{
    int fd = open(CONFIG_FILE, O_RDONLY);
    if (fd < 0) return;

    char buf[256];
    read(fd, buf, sizeof(buf));
    close(fd);

    /* CWE-672: fd used after close */
    read(fd, buf + 128, 64);   /* VULN */
}

/*
 * CWE-188: reliance on data layout assumptions.
 * Struct layout assumed identical across architectures.
 */
typedef struct {
    uint8_t  type;
    /* Compiler may insert 3 bytes of padding here on 32-bit */
    uint32_t value;
} LayoutPacket;

void serialize_packet(LayoutPacket *pkt, uint8_t *out)
{
    /* CWE-188: raw memcpy of struct with padding – endian and layout unsafe */
    memcpy(out, pkt, sizeof(LayoutPacket));   /* VULN */
}


/* ============================================================
 *  Section 17: Audit & Compliance (Incomplete Controls)
 *  CWE-200, CWE-201, CWE-390, CWE-391, CWE-404
 * ============================================================ */

void audit_log(const char *user, const char *action, const char *resource)
{
    char record[512];
    /* CWE-134: user / action from external input, used as partial format */
    snprintf(record, sizeof(record), "AUDIT user=%s action=%s resource=%s",
             user, action, resource);

    FILE *fp = fopen(LOG_PATH, "a");
    if (!fp) {
        /* CWE-390: error detected (fopen failed) but audit silently dropped */
        return;   /* VULN: missing audit record is a compliance failure */
    }

    /* CWE-134: record used as format string */
    fprintf(fp, record);   /* VULN */
    fputc('\n', fp);
    fclose(fp);
}

/*
 * CWE-391: unchecked error condition – write errors silently ignored.
 * CWE-404: resource not released on error.
 */
int write_critical_data(const char *path, const void *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;

    ssize_t written = write(fd, data, len);
    /* CWE-391: partial write not checked – data integrity not guaranteed */
    if (written != (ssize_t)len) {
        /* CWE-404: fd not closed on this error path */
        return -1;   /* VULN: leaks fd */
    }

    /* CWE-391: fsync not called – data may not reach disk */
    close(fd);
    return 0;
}

/*
 * CWE-201: sensitive data in query string / GET parameters (log exposure).
 */
void log_http_get(const char *url)
{
    /* CWE-201: URL with password or token query params written to log */
    /* e.g. /api/login?user=admin&pass=secret123 */
    log_event(1, "GET %s", url);   /* VULN */
}


/* ============================================================
 *  Section 18: Defragmentation / Chunk Reassembly
 *  CWE-122, CWE-190, CWE-401, CWE-415, CWE-416
 * ============================================================ */

/*
 * Generic chunk reassembler – mirrors TCP/IP defrag and
 * VPN packet reassembly CVEs.
 * CWE-190: total_size computed via integer overflow.
 * CWE-122: reassembly buffer overflowed.
 */
void defrag_reassemble(DataChunk *chunks, int count)
{
    size_t total_size = 0;

    /* CWE-190: sum of chunk lengths may overflow */
    for (int i = 0; i < count; i++) {
        total_size += chunks[i].len;   /* VULN */
    }

    /* CWE-789: allocate overflowed / tiny size */
    uint8_t *out = (uint8_t *)malloc(total_size);   /* VULN */
    if (!out) return;

    size_t offset = 0;
    for (int i = 0; i < count; i++) {
        /* CWE-122: no check that offset + chunks[i].len <= total_size */
        memcpy(out + offset, chunks[i].data, chunks[i].len);   /* VULN */
        offset += chunks[i].len;

        /* CWE-843: interpret data pointer as different type */
        if (chunks[i].type == 0xFF) {
            /* Treat raw bytes as function pointer – type confusion */
            void (*fn)(void) = *(void (**)(void))chunks[i].data; /* VULN */
            fn();   /* VULN: control flow hijack */
        }
    }

    /* CWE-401: out never freed */
    process_tlv(out, (uint32_t)total_size);
}

/*
 * CWE-415 + CWE-416: double free via chunk->data reference sharing.
 */
void free_chunks(DataChunk *chunks, int count)
{
    for (int i = 0; i < count; i++) {
        free(chunks[i].data);   /* VULN: if two chunks share same data ptr */
    }
    /* CWE-416: chunks[].data used in defrag_reassemble after this */
}


/* ============================================================
 *  Section 19: Base64 / Encoding Utilities
 *  CWE-120, CWE-190, CWE-193, CWE-680
 * ============================================================ */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * CWE-120 / CWE-680: output buffer size not verified by caller.
 * Output is ceil(in_len/3)*4 bytes; if out is smaller → overflow.
 */
void encode_base64(const uint8_t *in, size_t in_len, char *out)
{
    size_t i, j = 0;
    for (i = 0; i + 2 < in_len; i += 3) {
        out[j++] = b64_table[(in[i] >> 2) & 0x3F];
        out[j++] = b64_table[((in[i] & 3) << 4) | (in[i+1] >> 4)];
        out[j++] = b64_table[((in[i+1] & 0xF) << 2) | (in[i+2] >> 6)];
        out[j++] = b64_table[in[i+2] & 0x3F];
    }
    /* Handle remaining bytes */
    if (i < in_len) {
        out[j++] = b64_table[(in[i] >> 2) & 0x3F];
        if (i + 1 < in_len) {
            out[j++] = b64_table[((in[i] & 3) << 4) | (in[i+1] >> 4)];
            out[j++] = '=';
        } else {
            out[j++] = b64_table[(in[i] & 3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    /* CWE-170: NUL terminator written at j, but out may not be large enough */
    out[j] = '\0';   /* VULN if out_size < j+1 */
}

/*
 * CWE-193: off-by-one in decode – stops one byte early.
 */
size_t decode_hex(const char *in, uint8_t *out, size_t out_sz)
{
    size_t len = strlen(in);
    size_t i;

    /* CWE-193: should be i < len but uses i < len - 1 → last byte ignored */
    for (i = 0; i + 1 < len - 1; i += 2) {   /* VULN */
        char hex[3] = { in[i], in[i+1], 0 };
        out[i / 2] = (uint8_t)strtoul(hex, NULL, 16);
    }
    return i / 2;
}

/*
 * Parse integer field – CWE-681: incorrect conversion.
 */
int parse_integer_field(const char *str, int base)
{
    long val = strtol(str, NULL, base);

    /* CWE-681: long silently truncated to int */
    return (int)val;   /* VULN: LONG_MAX → INT truncation */
}


/* ============================================================
 *  Section 20: Main Entry Point
 * ============================================================ */

static void print_banner(void)
{
    printf("=================================================\n");
    printf("  VulnApp Server v%s\n", VERSION);
    printf("  FOR SECURITY RESEARCH / SAST TESTING ONLY\n");

    /* CWE-200 / CWE-489: debug info printed at startup */
    if (g_debug) {
        printf("  [DEBUG] DB: %s@%s  pass: %s\n",
               g_db_user, g_db_host, g_db_pass);         /* VULN */
        printf("  [DEBUG] enc_key[0]: 0x%02X\n", g_enc_key[0]); /* VULN */
        printf("  [DEBUG] master_token: %s\n", g_master_token);  /* VULN: uninitialized */
    }
    printf("=================================================\n");
}

int main(int argc, char *argv[])
{
    char  username[128];
    char  password[64];
    char  input[MAX_CMD];
    int   port  = 8080;
    int   uid;
    char  session_id[64];

    print_banner();
    setup_signals();

    /* CWE-665: g_master_token never initialised – printed in banner above */

    if (argc >= 3) {
        /* CWE-120: argv copied without bounds check */
        strcpy(username, argv[1]);   /* VULN */
        strcpy(password, argv[2]);   /* VULN */
    } else {
        printf("Enter username: ");
        /* CWE-242: gets() – never use */
        gets(username);              /* VULN CWE-120/CWE-676 */

        printf("Enter password: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = '\0';
    }

    uid = authenticate(username, password);
    if (uid < 0) {
        fprintf(stderr, "Authentication failed (code %d)\n", uid); /* CWE-200 */
        return 1;
    }

    /* CWE-330: weak session */
    generate_session_id(session_id, sizeof(session_id));
    printf("Session: %s\n", session_id);

    /* Initialise user data */
    if (g_user_count < MAX_USERS) {
        UserRecord *u = &g_users[g_user_count++];
        /* CWE-665: struct partially initialised – password_hash, email left as garbage */
        u->id   = uid;
        strncpy(u->username, username, sizeof(u->username) - 1);
        u->role = (uid == 9999) ? 1 : 0;

        /* CWE-401: profile_blob allocated but never freed */
        u->profile_blob = allocate_profile(16, 1024);  /* VULN: may overflow */
    }

    /* Interactive command loop */
    while (1) {
        printf("%s> ", username);
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0)
            break;

        /* CWE-134: input used as format string */
        printf(input);        /* VULN */
        putchar('\n');

        /* CWE-78: "exec " prefix executes arbitrary command */
        if (strncmp(input, "exec ", 5) == 0) {
            system(input + 5);   /* VULN */
        }

        /* CWE-22: "get " prefix retrieves arbitrary file path */
        if (strncmp(input, "get ", 4) == 0) {
            char safe_path[MAX_PATH];
            char raw_path[MAX_PATH];
            strncpy(raw_path, input + 4, sizeof(raw_path) - 1);
            if (validate_path(UPLOAD_DIR, raw_path, safe_path, sizeof(safe_path)) == 0) {
                FILE *fp = fopen(safe_path, "r");
                if (fp) {
                    char fbuf[512];
                    while (fgets(fbuf, sizeof(fbuf), fp)) {
                        /* CWE-134: file content used as format string */
                        printf(fbuf);   /* VULN */
                    }
                    fclose(fp);
                }
            }
        }

        /* SQL query via user input */
        if (strncmp(input, "query ", 6) == 0) {
            execute_query("users", input + 6);   /* CWE-89 */
        }

        /* Plugin load */
        if (strncmp(input, "plugin ", 7) == 0) {
            load_plugin(input + 7);   /* CWE-426 */
        }

        /* Admin exec */
        if (strncmp(input, "admin ", 6) == 0) {
            admin_exec(uid, input + 6);   /* CWE-78 / CWE-285 */
        }

        /* Fetch URL */
        if (strncmp(input, "fetch ", 6) == 0) {
            fetch_url(input + 6);   /* CWE-88 / CWE-78 */
        }
    }

    /* CWE-200 / CWE-489: debug dump on exit */
    if (g_debug) {
        printf("[DEBUG] Exit. Total requests: %d\n", g_request_counter);
        printf("[DEBUG] DB password: %s\n", g_db_pass);   /* VULN */
        printf("[DEBUG] Enc key: %02X%02X%02X%02X\n",
               g_enc_key[0], g_enc_key[1], g_enc_key[2], g_enc_key[3]); /* VULN */
    }

    /* Start server in background */
    if (argc >= 4) {
        port = atoi(argv[3]);   /* CWE-606: no validation of port range */
        start_network_listener(port);
    }

    return 0;
}

/* ============================================================
 *  END OF vulnerable_realworld.c
 *  Total intentional vulnerability patterns: 80+
 *  Lines: 2100+
 *  FOR SECURITY RESEARCH / SAST BENCHMARK USE ONLY
 * ============================================================ */
