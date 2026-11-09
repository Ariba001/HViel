
#include <stdlib.h>
#include <string.h>
void CWE415_double_free__CWE415_bad(char *input) {
    char *p = (char *)malloc(64);
    strncpy(p, input, 63);
    free(p);
    free(p);
}
void CWE415_double_free__CWE415_good(char *input) {
    char *p = (char *)malloc(64);
    strncpy(p, input, 63);
    free(p);
    p = NULL;
}
void wrapper_CWE415(char *input) {
    CWE415_double_free__CWE415_bad(input);
    CWE415_double_free__CWE415_good(input);
}
int main(int argc, char **argv) { if (argc>1) wrapper_CWE415(argv[1]); return 0; }
