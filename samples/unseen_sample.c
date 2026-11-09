#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Buried 3 calls deep behind innocuous-looking wrappers -- this is the
   case the RF (per-function only) should struggle with more than the
   GNN (which can see call-graph context). */
void core_copy_CWE121_bad(char *input) {
    char buf[16];
    strcpy(buf, input);
    printf("%s\n", buf);
}
void level2_helper(char *input) {
    core_copy_CWE121_bad(input);
}
void level1_entry(char *input) {
    level2_helper(input);
}

/* A clean, safe sibling with the same wrapper depth. */
void core_copy_CWE121_good(char *input) {
    char buf[16];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("%s\n", buf);
}
void level2_helper_safe(char *input) {
    core_copy_CWE121_good(input);
}
void level1_entry_safe(char *input) {
    level2_helper_safe(input);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        level1_entry(argv[1]);
        level1_entry_safe(argv[1]);
    }
    return 0;
}
