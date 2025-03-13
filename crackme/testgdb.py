import gdb

flag_hex = list()

class DebugBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super(DebugBreakpoint,self).__init__("*0x00201af1")
    def stop(self):
        print("Past Debug")
        gdb.execute("set $eflags = 0")
        return False

class ReadECXBreakpoint(gdb.Breakpoint):
    flag_hex = list()
    def __init__(self):
        super(ReadECXBreakpoint,self).__init__("*0x00201dfd")
    def stop(self):
        self.flag_hex.append(gdb.parse_and_eval("$ecx"))
        return False

if __name__ == '__main__':
    gdb.execute("file /home/florian/Documents/SoftSec/crackme/crackme-x86_64-linux/crackme2")
    DebugBreakpoint()
    brk = ReadECXBreakpoint()
    print("Test")
    gdb.execute("run")
    flag = ''
    for val in brk.flag_hex[:-1]:
            flag += chr(val)
    print("Flag: "+flag)
    gdb.execute("q")
