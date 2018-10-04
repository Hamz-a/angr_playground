import angr
import claripy

path_to_bin = "../binaries/04_angr_symbolic_stack"


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

# Create the begin state starting from address 0x08048697 (see r2 output bellow)
# $ r2 -A 04_angr_symbolic_stack
# [0x08048390]> pdf @sym.handle_user
# ┌ (fcn) sym.handle_user 123
# │   sym.handle_user ();
# │           ; var unsigned int local_10h @ ebp-0x10
# │           ; var unsigned int local_ch @ ebp-0xc
# │           ; CALL XREF from sym.main (0x8048715)
# │           0x08048679      55             push ebp
# │           0x0804867a      89e5           mov ebp, esp
# │           0x0804867c      83ec18         sub esp, 0x18
# │           0x0804867f      83ec04         sub esp, 4
# │           0x08048682      8d45f0         lea eax, [local_10h]
# │           0x08048685      50             push eax
# │           0x08048686      8d45f4         lea eax, [local_ch]
# │           0x08048689      50             push eax
# │           0x0804868a      68b3870408     push str.u__u               ; 0x80487b3 ; "%u %u" ; const char *format
# │           0x0804868f      e8dcfcffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
# │           0x08048694      83c410         add esp, 0x10
# │           0x08048697      8b45f4         mov eax, dword [local_ch]    <<< Start here
# │           0x0804869a      83ec0c         sub esp, 0xc
# │           0x0804869d      50             push eax
# │           0x0804869e      e806feffff     call sym.complex_function0
# │           0x080486a3      83c410         add esp, 0x10
# │           0x080486a6      8945f4         mov dword [local_ch], eax
# │           0x080486a9      8b45f0         mov eax, dword [local_10h]
# │           0x080486ac      83ec0c         sub esp, 0xc
# │           0x080486af      50             push eax
# │           0x080486b0      e8dcfeffff     call sym.complex_function1
# │           0x080486b5      83c410         add esp, 0x10
# │           0x080486b8      8945f0         mov dword [local_10h], eax
# │           0x080486bb      8b45f4         mov eax, dword [local_ch]
# │           0x080486be      3dd1243077     cmp eax, 0x773024d1
# │       ┌─< 0x080486c3      750a           jne 0x80486cf
# │       │   0x080486c5      8b45f0         mov eax, dword [local_10h]
# │       │   0x080486c8      3dcf1143bc     cmp eax, 0xbc4311cf
# │      ┌──< 0x080486cd      7412           je 0x80486e1
# │      ││   ; CODE XREF from sym.handle_user (0x80486c3)
# │      │└─> 0x080486cf      83ec0c         sub esp, 0xc
# │      │    0x080486d2      68b9870408     push str.Try_again.         ; 0x80487b9 ; "Try again." ; const char *s
# │      │    0x080486d7      e874fcffff     call sym.imp.puts           ; int puts(const char *s)
# │      │    0x080486dc      83c410         add esp, 0x10
# │      │┌─< 0x080486df      eb10           jmp 0x80486f1
# │      ││   ; CODE XREF from sym.handle_user (0x80486cd)
# │      └──> 0x080486e1      83ec0c         sub esp, 0xc
# │       │   0x080486e4      68c4870408     push str.Good_Job.          ; 0x80487c4 ; "Good Job." ; const char *s
# │       │   0x080486e9      e862fcffff     call sym.imp.puts           ; int puts(const char *s)
# │       │   0x080486ee      83c410         add esp, 0x10
# │       │   ; CODE XREF from sym.handle_user (0x80486df)
# │       └─> 0x080486f1      90             nop
# │           0x080486f2      c9             leave
# └           0x080486f3      c3             ret
entry_state = project.factory.blank_state(addr=0x08048697)

# Create a Symbolic BitVectors for each part of the password (32 bits per part)
password_part0 = claripy.BVS("password_part0", 32)
password_part1 = claripy.BVS("password_part1", 32)


# Setup the stack manually since we're injecting the BVS on the stack in the middle of a function
entry_state.regs.ebp = entry_state.regs.esp
entry_state.regs.esp -= 8
entry_state.stack_push(password_part0)
entry_state.stack_push(password_part1)


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
    print("{} {}".format(solution0, solution1))
else:
    print("No path found...")