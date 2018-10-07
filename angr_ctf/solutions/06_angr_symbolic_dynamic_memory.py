import angr
import claripy

path_to_bin = "../binaries/06_angr_symbolic_dynamic_memory"


# Find callback
def good_job(state):
    # Get the output of the state
    stdout = state.posix.dumps(1)
    # If the program echo'ed "Good Job." then we've found a good state
    return "Good Job." in str(stdout)


# Avoid callback
def try_again(state):
    # Get the output of the state
    stdout = state.posix.dumps(1)
    # If the program echo'ed "Try again." then we found a state that we want to avoid
    return "Try again." in str(stdout)


# Create an angr project
project = angr.Project(path_to_bin)

# Create the begin state starting from address 0x08048699 (see r2 output bellow)
# $ r2 -A 06_angr_symbolic_dynamic_memory
# [0x08048490]> pdf @main
# ┌ (fcn) main 395
# │   main (int argc, char **argv, char **envp);
# │   <REDACTED>
# │           0x08048664      e8e7fdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
# │           0x08048669      83c410         add esp, 0x10
# │           0x0804866c      83ec0c         sub esp, 0xc
# │           0x0804866f      682e880408     push str.Enter_the_password: ; 0x804882e ; "Enter the password: " ; const char *format
# │           0x08048674      e877fdffff     call sym.imp.printf         ; int printf(const char *format)
# │           0x08048679      83c410         add esp, 0x10
# │           0x0804867c      8b15acc8bc0a   mov edx, dword [obj.buffer1] ; [0xabcc8ac:4]=0
# │           0x08048682      a1a4c8bc0a     mov eax, dword [obj.buffer0] ; [0xabcc8a4:4]=0
# │           0x08048687      83ec04         sub esp, 4
# │           0x0804868a      52             push edx
# │           0x0804868b      50             push eax
# │           0x0804868c      6843880408     push str.8s__8s             ; 0x8048843 ; "%8s %8s" ; const char *format
# │           0x08048691      e8cafdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
# │           0x08048696      83c410         add esp, 0x10
# │           0x08048699      c745f4000000.  mov dword [local_ch], 0     ; <<< START HERE
# │       ┌─< 0x080486a0      eb64           jmp 0x8048706
entry_state = project.factory.blank_state(addr=0x08048699)

# Create a Symbolic BitVectors for each part of the password (64 bits per part %8s is used in scanf)
password_part0 = claripy.BVS("password_part0", 64)
password_part1 = claripy.BVS("password_part1", 64)

# Setup some heap space
entry_state.memory.store(0xabcc8a4, 0x4000000, endness=project.arch.memory_endness)
entry_state.memory.store(0xabcc8ac, 0x4000A00, endness=project.arch.memory_endness)

# Use the created heap and inject BVS
entry_state.memory.store(0x4000000, password_part0)
entry_state.memory.store(0x4000A00, password_part1)

# Create a simulation manager
simulation_manager = project.factory.simulation_manager(entry_state)

# Pass callbacks for states that we should find and avoid
simulation_manager.explore(avoid=try_again, find=good_job)

# If simulation manager has found a state
if simulation_manager.found:
    found_state = simulation_manager.found[0]
    # Get flag by solving the symbolic values using the found path
    solution0 = found_state.solver.eval(password_part0, cast_to=bytes)
    solution1 = found_state.solver.eval(password_part1, cast_to=bytes)
    print("{} {}".format(solution0.decode("utf-8"), solution1.decode("utf-8")))
else:
    print("No path found...")