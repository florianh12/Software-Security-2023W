#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>

typedef char* caddr_t;
typedef uint32_t* waddr_t;

#define EXPECTED 0x4dd62388
uint32_t COPY[] = {0xfa1e0ff3,0xe5894855,0xfc35d90,0x441f,0xfa1e0ff3,0xe5894855,0x10ec8348,0xbf,0xb800,0x95e80000,0x89fffffe,0x7d83fc45,0x2475fffc,0x340941be,0x58d4867,0xd98,0xb8c78948,0x0,0xfffe63e8,0xb8ff,0xc70000,0x2a,0xfc3c990,0x441f,0xfa1e0ff3,0xe5894855,0xe87d8948,0xe0758948,0xe8458b48,0xdf35008b,0x89aa4ea9,0xeebfc45,0xe8458348,0x458b4804,0x31008be8,0x8b48fc45,0x3b48e845,0xe872e045,0x5dfc458b,0x1f0fc3};

void BEGIN() { }
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
        waddr_t address = (waddr_t)BEGIN;
        for(size_t i = 0; i <sizeof(COPY) / sizeof(uint32_t);i++) {
            *address = COPY[i];
            address++;
        }
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
