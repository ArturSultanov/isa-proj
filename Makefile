# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -pedantic -O2

# Libraries
LIBS = -lpcap -lncurses

# Target executable
TARGET = isa-top

# Source files
SRCS = isa-top.c

# Object files
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link the target executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Clean up object files and executable
clean:
	rm -f $(OBJS) $(TARGET)

# Run the program with default arguments (customize this)
run: $(TARGET)
	sudo ./$(TARGET) -i eth0 -s b -t 1  # Modify interface or options as needed
