import angr

path_to_bin = "../binaries/01_angr_avoid"

# Create an angr project
project = angr.Project(path_to_bin)

# Create the begin state starting from the entry point
entry_state = project.factory.entry_state(args=[path_to_bin])

# Create a simulation manager
simulation_manager = project.factory.simulation_manager(entry_state)

# Explore the path to "Good Job. while avoiding the fail path "Try again."
simulation_manager.explore(avoid=0x80485a8, find=0x80485dd)

# If simulation manager has found a state
if simulation_manager.found:
    found_state = simulation_manager.found[0]
    # Dump the input that was fed to the binary to get to this state
    input_str = found_state.posix.dumps(0)
    print(input_str)
else:
    print("No path found...")