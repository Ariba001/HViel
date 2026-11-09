
#include <stdio.h>
#include <stdlib.h>
int CWE327_weak_crypto__CWE327_bad(void) {
    srand(1234);
    return rand();
}
int CWE327_weak_crypto__CWE327_good(void) {
    FILE *f = fopen("/dev/urandom", "rb");
    int val = 0;
    if (f) { fread(&val, sizeof(val), 1, f); fclose(f); }
    return val;
}
int wrapper_CWE327(void) {
    return CWE327_weak_crypto__CWE327_bad() + CWE327_weak_crypto__CWE327_good();
}
int main(void) { return wrapper_CWE327(); }
