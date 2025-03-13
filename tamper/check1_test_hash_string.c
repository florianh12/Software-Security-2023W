#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>

typedef char* caddr_t;
typedef uint32_t* waddr_t;

#define EXPECTED 0x23275028
#define BIN "/bin/sh\0\0\0\0"

uint32_t hash(waddr_t addr, waddr_t end)
{
    uint32_t h = *addr ^ 0xaa4ea9df;
    while (addr < end) {
        addr++;
        h ^= *addr;
    }
    return h;
}


int main(int argv, char** argc)
{
    char* bin_sh = BIN;
    printf("Hash of '/bin/sh': 0x%x\n",hash((waddr_t)bin_sh,(waddr_t)(bin_sh + sizeof(bin_sh))));
}
