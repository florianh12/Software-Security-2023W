import angr
import claripy
project = angr.Project('./keygen', load_options={'auto_load_libs': False})
argv1 = claripy.BVS('argv1', 128)
initial_state = project.factory.entry_state(args=['./keygen', argv1])
sm = project.factory.simulation_manager(initial_state)
sm.explore(find=0x401a5a, avoid=0x400760)
result = sm.found[0]
print(result.solver.eval(argv1, cast_to=bytes))