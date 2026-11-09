
#include <stdio.h>
#include <string.h>
void CWE22_path_traversal__CWE22_bad(char *filename) {
    char path[256];
    snprintf(path, sizeof(path), "/data/%s", filename);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}
void CWE22_path_traversal__CWE22_good(char *filename) {
    if (strstr(filename, "..") != NULL) return;
    char path[256];
    snprintf(path, sizeof(path), "/data/%s", filename);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}
void wrapper_CWE22(char *filename) {
    CWE22_path_traversal__CWE22_bad(filename);
    CWE22_path_traversal__CWE22_good(filename);
}
int main(int argc, char **argv) { if (argc>1) wrapper_CWE22(argv[1]); return 0; }
