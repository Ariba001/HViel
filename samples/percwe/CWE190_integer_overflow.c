
#include <stdlib.h>
#include <string.h>
void CWE190_integer_overflow__CWE190_bad(int count) {
    int size = count * 1024;
    char *buf = (char *)malloc(size);
    if (buf) { memset(buf, 0, size); free(buf); }
}
void CWE190_integer_overflow__CWE190_good(int count) {
    if (count < 0 || count > 1000000) return;
    long size = (long)count * 1024;
    char *buf = (char *)malloc(size);
    if (buf) { memset(buf, 0, size); free(buf); }
}
void wrapper_CWE190(int n) {
    CWE190_integer_overflow__CWE190_bad(n);
    CWE190_integer_overflow__CWE190_good(n);
}
int main(int argc, char **argv) { wrapper_CWE190(argc); return 0; }
