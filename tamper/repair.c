#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>

typedef char* caddr_t;
typedef uint32_t* waddr_t;

#define EXPECTED 0x0
uint32_t COPY[] = {};

void BEGIN() { }
int is_being_debugged()
{
    int s = 0 /* TODO */;
    if (s == -1) {
        printf("Program is being debugged: 0x%08X\n", 0x67340941);
        *((int*)NULL) = 42;
    }
}

uint32_t hash(waddr_t addr, waddr_t end)
{
    uint32_t h = *addr ^ 0xaa4ea9df;
    int i;
    while (addr < end) {
        addr++;
        h ^= *addr;
    }
    return h;
}
void END() { }

void check()
{
    uint32_t h = hash((waddr_t)BEGIN, (waddr_t)END);
    if (h != EXPECTED) {
        puts("is_being_debugged() has been modified!\n");
        *((int*)NULL) = 9;
    }
}

void dump()
{
    uint32_t h = hash((waddr_t)BEGIN, (waddr_t)END);
    printf("#define EXPECTED 0x%x\n", h);

    printf("uint32_t COPY[] = {");
    waddr_t addr = (waddr_t)BEGIN;
    while (addr < (waddr_t)END) {
        printf("0x%x", *addr);
        addr++;
        if (addr < (waddr_t)END)
            printf(",");
    }
    printf("};\n");
    exit(0);
}

void make_code_writeable(caddr_t first, caddr_t last)
{
    caddr_t firstpage = first - ((long)first % getpagesize());
    caddr_t lastpage = last - ((long)last % getpagesize());
    int pages = (lastpage - firstpage) / getpagesize() + 1;
    if (mprotect(firstpage, pages * getpagesize(),
            PROT_READ | PROT_EXEC | PROT_WRITE)
        == -1)
        perror("mprotect");
}

int main(int argv, char** argc)
{
    if (argv > 1)
        dump();
    else {
        make_code_writeable((caddr_t)BEGIN, (caddr_t)END);
        check();
    }
    is_being_debugged();
}
