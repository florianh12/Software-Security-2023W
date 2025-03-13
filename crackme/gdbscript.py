import gdb

class DebugBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super(DebugBreakpoint,self).__init__(0x201b31)
    def stop(self):
        print("Yey")
        return False

if __name__ == '__main__':
    DebugBreakpoint()
    print("Test")
    gdb.execute("run")
