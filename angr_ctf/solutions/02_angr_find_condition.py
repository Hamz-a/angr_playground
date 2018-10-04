import angr

path_to_bin = "../binaries/02_angr_find_condition"


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

# Create the begin state starting from the entry point
entry_state = project.factory.entry_state(args=[path_to_bin])

# Create a simulation manager
simulation_manager = project.factory.simulation_manager(entry_state)

# Pass callbacks for states that we should find and avoid
simulation_manager.explore(avoid=try_again, find=good_job)

# If simulation manager has found a state
if simulation_manager.found:
    found_state = simulation_manager.found[0]
    # Dump the input that was fed to the binary to get to this state
    input_str = found_state.posix.dumps(0)
    print(input_str) # Get flag!
else:
    print("No path found...")