import angr
import claripy

path_to_bin = "../binaries/03_angr_symbolic_registers"


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
project = angr.Project(path_to_bin, auto_load_libs=False)

# Create a Symbolic BitVectors for each part of the password (32 bits per part)
password_part0 = claripy.BVS("password_part0", 32)
password_part1 = claripy.BVS("password_part1", 32)
password_part2 = claripy.BVS("password_part2", 32)

# Create the begin state starting from address 0x8048980 (see r2 output bellow)
# $ r2 -A 03_angr_symbolic_registers
# [0x080483f0]> s main
# [0x0804895a]> pdf
# ┌ (fcn) main 171
# │   main (int argc, char **argv, char **envp);
# │           ; DATA XREF from entry0 (0x8048407)
# │           <<< OMITTED >>>
# │           0x0804896e      689c8a0408     push str.Enter_the_password: ; 0x8048a9c ; "Enter the password: " ; const char *format
# │           0x08048973      e818faffff     call sym.imp.printf         ; int printf(const char *format)
# │           0x08048978      83c410         add esp, 0x10
# │           0x0804897b      e88cffffff     call sym.get_user_input
# │           0x08048980      8945ec         mov dword [local_14h], eax   <<<< FROM HERE
# │           0x08048983      895df0         mov dword [local_10h], ebx
# │           0x08048986      8955f4         mov dword [local_ch], edx
# │           0x08048989      83ec0c         sub esp, 0xc
# │           0x0804898c      ff75ec         push dword [local_14h]
# │           0x0804898f      e875fbffff     call sym.complex_function_1
# │           0x08048994      83c410         add esp, 0x10
# │           0x08048997      89c1           mov ecx, eax
# │           0x08048999      894dec         mov dword [local_14h], ecx
# │           0x0804899c      83ec0c         sub esp, 0xc
# │           0x0804899f      ff75f0         push dword [local_10h]
# │           0x080489a2      e8b3fcffff     call sym.complex_function_2
# │           0x080489a7      83c410         add esp, 0x10
# │           0x080489aa      89c1           mov ecx, eax
# │           0x080489ac      894df0         mov dword [local_10h], ecx
# │           0x080489af      83ec0c         sub esp, 0xc
# │           0x080489b2      ff75f4         push dword [local_ch]
# │           0x080489b5      e823feffff     call sym.complex_function_3
# │           <<< OMITTED >>>
# └           0x08048a04      c3             ret
entry_state = project.factory.blank_state(addr=0x8048980)

# Assign the registers used in the program to the declared symbolic bitvectors
entry_state.regs.eax = password_part0
entry_state.regs.ebx = password_part1
entry_state.regs.edx = password_part2

# Create a simulation manager
simulation_manager = project.factory.simulation_manager(entry_state)

# Pass callbacks for states that we should find and avoid
simulation_manager.explore(avoid=try_again, find=good_job)

# If simulation manager has found a state
if simulation_manager.found:
    found_state = simulation_manager.found[0]
    # Get flag by solving the symbolic values using the found path
    solution0 = found_state.solver.eval(password_part0, cast_to=int)
    solution1 = found_state.solver.eval(password_part1, cast_to=int)
    solution2 = found_state.solver.eval(password_part2, cast_to=int)
    print("{:x} {:x} {:x}".format(solution0, solution1, solution2))
else:
    print("No path found...")