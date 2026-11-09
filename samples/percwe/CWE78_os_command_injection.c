
#include <stdio.h>
#include <stdlib.h>
void CWE78_os_command_injection__CWE78_bad(char *input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo %s", input);
    system(cmd);
}
void CWE78_os_command_injection__CWE78_good(char *input) {
    printf("would echo: %s\n", input);
}
void wrapper_CWE78(char *input) {
    CWE78_os_command_injection__CWE78_bad(input);
    CWE78_os_command_injection__CWE78_good(input);
}
int main(int argc, char **argv) { if (argc>1) wrapper_CWE78(argv[1]); return 0; }
