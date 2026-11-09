
#include <stdio.h>
#include <string.h>
void CWE476_null_deref__CWE476_bad(char *input) {
    char *p = strchr(input, 'x');
    printf("%c\n", *p);
}
void CWE476_null_deref__CWE476_good(char *input) {
    char *p = strchr(input, 'x');
    if (p) printf("%c\n", *p);
}
void wrapper_CWE476(char *input) {
    CWE476_null_deref__CWE476_bad(input);
    CWE476_null_deref__CWE476_good(input);
}
int main(int argc, char **argv) { if (argc>1) wrapper_CWE476(argv[1]); return 0; }
