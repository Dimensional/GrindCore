/* Load libGrindCore.so the way a plain C program would: no -lm, no -pthread, RTLD_NOW (audit/build-exam.md B1).
   cc -o loadso loadso.c -ldl && ./loadso <path>/libGrindCore.so */
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    printf("%s: %s\n", argv[1], h ? "loaded" : dlerror());
    return h ? 0 : 1;
}
