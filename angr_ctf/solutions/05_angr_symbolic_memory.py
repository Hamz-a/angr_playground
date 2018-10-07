import angr
import claripy

path_to_bin = "../binaries/05_angr_symbolic_memory"


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

# Create the begin state starting from address 0x080485fe (see r2 output bellow)
# $ r2 -A 05_angr_symbolic_memory
# [0x08048430]> pdf @main
# ┌ (fcn) main 223
# │   main (int argc, char **argv, char **envp);
# │           ; var signed int local_ch @ ebp-0xc
# │           ; var int local_4h @ ebp-0x4
# │           ; arg int arg_4h @ esp+0x4
# │           ; DATA XREF from entry0 (0x8048447)
# │           0x080485a8      8d4c2404       lea ecx, [arg_4h]           ; 4
# │           0x080485ac      83e4f0         and esp, 0xfffffff0
# │           0x080485af      ff71fc         push dword [ecx - 4]
# │           0x080485b2      55             push ebp
# │           0x080485b3      89e5           mov ebp, esp
# │           0x080485b5      51             push ecx
# │           0x080485b6      83ec14         sub esp, 0x14
# │           0x080485b9      83ec04         sub esp, 4
# │           0x080485bc      6a21           push 0x21                   ; '!' ; 33 ; size_t n
# │           0x080485be      6a00           push 0                      ; int c
# │           0x080485c0      68c0a11b0a     push obj.user_input         ; 0xa1ba1c0 ; void *s
# │           0x080485c5      e826feffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
# │           0x080485ca      83c410         add esp, 0x10
# │           0x080485cd      83ec0c         sub esp, 0xc
# │           0x080485d0      681e870408     push str.Enter_the_password: ; 0x804871e ; "Enter the password: " ; const char *format
# │           0x080485d5      e8d6fdffff     call sym.imp.printf         ; int printf(const char *format)
# │           0x080485da      83c410         add esp, 0x10
# │           0x080485dd      83ec0c         sub esp, 0xc
# │           0x080485e0      68d8a11b0a     push 0xa1ba1d8
# │           0x080485e5      68d0a11b0a     push 0xa1ba1d0
# │           0x080485ea      68c8a11b0a     push 0xa1ba1c8
# │           0x080485ef      68c0a11b0a     push obj.user_input         ; 0xa1ba1c0
# │           0x080485f4      6833870408     push str.8s__8s__8s__8s     ; 0x8048733 ; "%8s %8s %8s %8s" ; const char *format
# │           0x080485f9      e802feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
# │           0x080485fe      83c420         add esp, 0x20                ; <<< START HERE
# │           0x08048601      c745f4000000.  mov dword [local_ch], 0
# │       ┌─< 0x08048608      eb2d           jmp 0x8048637
entry_state = project.factory.blank_state(addr=0x080485fe)

# Create a Symbolic BitVectors for each part of the password (64 bits per part %8s is used in scanf)
password_part0 = claripy.BVS("password_part0", 64)
password_part1 = claripy.BVS("password_part1", 64)
password_part2 = claripy.BVS("password_part2", 64)
password_part3 = claripy.BVS("password_part3", 64)

# Store the BVS in memory
entry_state.memory.store(0xa1ba1c0, password_part0)
entry_state.memory.store(0xa1ba1c8, password_part1)
entry_state.memory.store(0xa1ba1d0, password_part2)
entry_state.memory.store(0xa1ba1d8, password_part3)


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
    solution2 = found_state.solver.eval(password_part2, cast_to=bytes)
    solution3 = found_state.solver.eval(password_part3, cast_to=bytes)
    print("{} {} {} {}".format(solution0.decode("utf-8"), solution1.decode("utf-8"), solution2.decode("utf-8"), solution3.decode("utf-8")))
else:
    print("No path found...")