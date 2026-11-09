
#include <stdio.h>
#include <string.h>
void CWE121_stack_buffer_overflow__CWE121_bad(char *input) {
    char buf[16];
    strcpy(buf, input);
    printf("%s\n", buf);
}
void CWE121_stack_buffer_overflow__CWE121_good(char *input) {
    char buf[16];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("%s\n", buf);
}
void wrapper_CWE121(char *input) {
    CWE121_stack_buffer_overflow__CWE121_bad(input);
    CWE121_stack_buffer_overflow__CWE121_good(input);
}
int main(int argc, char **argv) { if (argc>1) wrapper_CWE121(argv[1]); return 0; }
