# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra

# Libraries
LDFLAGS = -lpcap -lncurses

# Target executable
TARGET = isa-top

# Source files
SRCS = main.c config.c connection.c display.c packet_logic.c utils.c

# Object files
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link the target executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Clean up object files and executable
clean:
	rm -f $(OBJS) $(TARGET)

# Run the program with default arguments
run: $(TARGET)
	sudo ./$(TARGET) -i $(IFACE) -s b -t 1

# Run valgrind command to check the memory leaks
valgrind: $(TARGET)
	sudo valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) -i $(IFACE)
