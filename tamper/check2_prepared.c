#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

typedef char* caddr_t;
typedef uint32_t* waddr_t;

#define EXPECTED1 0x1dd6d008
#define EXPECTED2 0x1b338f12

void BEGIN1() { }
int is_being_debugged()
{
    int s = ptrace(PTRACE_TRACEME);
    if (s == -1) {
        printf("Program is being debugged: 0x%08X\n", 0x67340941);
        *((int*)NULL) = 42;
    }
}

uint32_t hash(waddr_t addr, waddr_t end)
{
    uint32_t h = *addr ^ 0xaa4ea9df;
    while (addr < end) {
        addr++;
        h ^= *addr;
    }
    return h;
}
void END1() { }


void BEGIN2() { }
void check()
{
    uint32_t h = hash((waddr_t)BEGIN1, (waddr_t)END1);
    if (h != EXPECTED1) {
        puts("is_being_debugged() has been modified!\n");
        *((int*)NULL) = 9;
    }
}
void END2() { }

void check2()
{
    uint32_t h = hash((waddr_t)BEGIN2, (waddr_t)END2);
    if (h != EXPECTED2) {
        puts("check() has been modified!\n");
        *((int*)NULL) = 21;
    }
}

void dump()
{
    uint32_t h;

    h = hash((waddr_t)BEGIN1, (waddr_t)END1);
    printf("#define EXPECTED1 0x%x\n", h);
    h = hash((waddr_t)BEGIN2, (waddr_t)END2);
    printf("#define EXPECTED2 0x%x\n", h);
    exit(0);
}

int main(int argv, char** argc)
{
    if (argv > 1)
        dump();
    else {
        check();
        check2();
    }
    is_being_debugged();
}
