#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---------- CWE-121: Stack-based buffer overflow ---------- */
void CWE121_stack_buffer_overflow__CWE121_bad(char *input) {
    char buf[16];
    strcpy(buf, input);          /* no bounds check */
    printf("%s\n", buf);
}
void CWE121_stack_buffer_overflow__CWE121_good(char *input) {
    char buf[16];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("%s\n", buf);
}

/* ---------- CWE-78: OS command injection ---------- */
void CWE78_os_command_injection__CWE78_bad(char *input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo %s", input);
    system(cmd);                 /* unsanitized input into system() */
}
void CWE78_os_command_injection__CWE78_good(char *input) {
    printf("would echo: %s\n", input);  /* never shells out */
}

/* ---------- CWE-134: Format string vulnerability ---------- */
void CWE134_format_string__CWE134_bad(char *input) {
    printf(input);                /* attacker controls format string */
}
void CWE134_format_string__CWE134_good(char *input) {
    printf("%s", input);
}

/* ---------- CWE-190: Integer overflow ---------- */
void CWE190_integer_overflow__CWE190_bad(int count) {
    int size = count * 1024;      /* can overflow, used unchecked */
    char *buf = (char *)malloc(size);
    if (buf) { memset(buf, 0, size); free(buf); }
}
void CWE190_integer_overflow__CWE190_good(int count) {
    if (count < 0 || count > 1000000) return;
    long size = (long)count * 1024;
    char *buf = (char *)malloc(size);
    if (buf) { memset(buf, 0, size); free(buf); }
}

/* ---------- CWE-415: Double free ---------- */
void CWE415_double_free__CWE415_bad(char *input) {
    char *p = (char *)malloc(64);
    strncpy(p, input, 63);
    free(p);
    free(p);                      /* double free */
}
void CWE415_double_free__CWE415_good(char *input) {
    char *p = (char *)malloc(64);
    strncpy(p, input, 63);
    free(p);
    p = NULL;
}

/* ---------- CWE-476: NULL pointer dereference ---------- */
void CWE476_null_deref__CWE476_bad(char *input) {
    char *p = strchr(input, 'x');
    printf("%c\n", *p);           /* strchr may return NULL */
}
void CWE476_null_deref__CWE476_good(char *input) {
    char *p = strchr(input, 'x');
    if (p) printf("%c\n", *p);
}

/* ---------- CWE-327: Weak/broken crypto (predictable "random") ---------- */
int CWE327_weak_crypto__CWE327_bad(void) {
    srand(1234);                  /* fixed seed, predictable */
    return rand();
}
int CWE327_weak_crypto__CWE327_good(void) {
    FILE *f = fopen("/dev/urandom", "rb");
    int val = 0;
    if (f) { fread(&val, sizeof(val), 1, f); fclose(f); }
    return val;
}

/* ---------- CWE-22: Path traversal ---------- */
void CWE22_path_traversal__CWE22_bad(char *filename) {
    char path[256];
    snprintf(path, sizeof(path), "/data/%s", filename);
    FILE *f = fopen(path, "r");   /* filename not sanitized, allows ../ */
    if (f) fclose(f);
}
void CWE22_path_traversal__CWE22_good(char *filename) {
    if (strstr(filename, "..") != NULL) return;  /* reject traversal */
    char path[256];
    snprintf(path, sizeof(path), "/data/%s", filename);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

/* ---------- Helper / wrapper functions (unlabeled, test the GNN's point) ---------- */
void wrapper_calls_bad_copy(char *input) {
    CWE121_stack_buffer_overflow__CWE121_bad(input);
}
void wrapper_calls_good_copy(char *input) {
    CWE121_stack_buffer_overflow__CWE121_good(input);
}
void dispatch_everything(char *input, int n) {
    CWE121_stack_buffer_overflow__CWE121_bad(input);
    CWE121_stack_buffer_overflow__CWE121_good(input);
    CWE78_os_command_injection__CWE78_bad(input);
    CWE78_os_command_injection__CWE78_good(input);
    CWE134_format_string__CWE134_bad(input);
    CWE134_format_string__CWE134_good(input);
    CWE190_integer_overflow__CWE190_bad(n);
    CWE190_integer_overflow__CWE190_good(n);
    CWE415_double_free__CWE415_bad(input);
    CWE415_double_free__CWE415_good(input);
    CWE476_null_deref__CWE476_bad(input);
    CWE476_null_deref__CWE476_good(input);
    CWE22_path_traversal__CWE22_bad(input);
    CWE22_path_traversal__CWE22_good(input);
    wrapper_calls_bad_copy(input);
    wrapper_calls_good_copy(input);
}

int main(int argc, char **argv) {
    if (argc > 1) dispatch_everything(argv[1], argc);
    CWE327_weak_crypto__CWE327_bad();
    CWE327_weak_crypto__CWE327_good();
    return 0;
}
