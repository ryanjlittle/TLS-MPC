# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc

# Include any dependencies generated for this target.
include CMakeFiles/aesgcm.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/aesgcm.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/aesgcm.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/aesgcm.dir/flags.make

CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o: CMakeFiles/aesgcm.dir/flags.make
CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o: test/aesgcm.cpp
CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o: CMakeFiles/aesgcm.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ryan/Research/ThresholdPassword/TLS-1.2/mpc/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o -MF CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o.d -o CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o -c /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc/test/aesgcm.cpp

CMakeFiles/aesgcm.dir/test/aesgcm.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aesgcm.dir/test/aesgcm.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc/test/aesgcm.cpp > CMakeFiles/aesgcm.dir/test/aesgcm.cpp.i

CMakeFiles/aesgcm.dir/test/aesgcm.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aesgcm.dir/test/aesgcm.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc/test/aesgcm.cpp -o CMakeFiles/aesgcm.dir/test/aesgcm.cpp.s

# Object files for target aesgcm
aesgcm_OBJECTS = \
"CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o"

# External object files for target aesgcm
aesgcm_EXTERNAL_OBJECTS =

bin/aesgcm: CMakeFiles/aesgcm.dir/test/aesgcm.cpp.o
bin/aesgcm: CMakeFiles/aesgcm.dir/build.make
bin/aesgcm: /usr/lib/libssl.so
bin/aesgcm: /usr/lib/libcrypto.so
bin/aesgcm: /usr/local/lib/libemp-tool.so
bin/aesgcm: CMakeFiles/aesgcm.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ryan/Research/ThresholdPassword/TLS-1.2/mpc/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bin/aesgcm"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/aesgcm.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/aesgcm.dir/build: bin/aesgcm
.PHONY : CMakeFiles/aesgcm.dir/build

CMakeFiles/aesgcm.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/aesgcm.dir/cmake_clean.cmake
.PHONY : CMakeFiles/aesgcm.dir/clean

CMakeFiles/aesgcm.dir/depend:
	cd /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc /home/ryan/Research/ThresholdPassword/TLS-1.2/mpc/CMakeFiles/aesgcm.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/aesgcm.dir/depend

