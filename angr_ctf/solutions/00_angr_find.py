import angr

path_to_bin = "../binaries/00_angr_find"

# Create an angr project
project = angr.Project(path_to_bin)

# Create the begin state starting from the entry point
entry_state = project.factory.entry_state(args=[path_to_bin])

# Create a simulation manager
simulation_manager = project.factory.simulation_manager(entry_state)

# Explore the path to "Good Job."
simulation_manager.explore(find=0x08048675)

# If simulation manager has found a state
if simulation_manager.found:
    found_state = simulation_manager.found[0]
    # Dump the input that was fed to the binary to get to this state
    input_str = found_state.posix.dumps(0)
    print(input_str) # Get flag!
else:
    print("No path found...")