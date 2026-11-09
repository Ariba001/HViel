
#include <stdio.h>
void CWE134_format_string__CWE134_bad(char *input) {
    printf(input);
}
void CWE134_format_string__CWE134_good(char *input) {
    printf("%s", input);
}
void wrapper_CWE134(char *input) {
    CWE134_format_string__CWE134_bad(input);
    CWE134_format_string__CWE134_good(input);
}
int main(int argc, char **argv) { if (argc>1) wrapper_CWE134(argv[1]); return 0; }
