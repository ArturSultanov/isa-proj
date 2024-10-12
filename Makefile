# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -pedantic -Wextra -Werror -g

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

# Run the program with default arguments
run: $(TARGET)
	sudo ./$(TARGET) -i lo -s b -t 1  # localhost as default

# Run valgrind command to check the memory leaks
valgrind: $(TARGET)
	sudo valgrind --leak-check=full ./$(TARGET) -i lo
