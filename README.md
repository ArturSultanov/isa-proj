# Application for obtaining network traffic statistics

The program is designed to capture the network packages and displays the current bit rates for each communicating IP address.

- Author: Artur Sultanov
- xlogin: xsulta01
- year: 2024/25

## Requirements:

### Libraries:

- `libpcap`: For packet capturing.
- `ncurses`: For creating a text-based user interface.

### Environment:

- A GNU/Linux operating system.
- GCC compiler.

## Usage:

`isa-top -i int [-s b|p]`

- `-i int`: rozhraní, na kterém aplikace naslouchá
- `-s b|p`: seřazení výstupu podle počtu bajtů/paketů/s

## Implementation

The functional parts of the program are described below:

### Command-Line Arguments Parsing

The `parse_args` function is responsible for parsing the arguments provided by the user when running the program. These arguments include:

-i interface: Specifies the network interface (e.g., eth0, wlan0) that the program should listen to for network traffic.
-s b|p: Optional flag to specify the sorting mode. If set to b, the connections will be sorted by bytes per second; if p, they will be sorted by packets per second. The default is to sort by bytes.
-t interval: Optional flag to set how often (in seconds) the statistics should be updated. By default, this is 1 second.
If the required -i flag (interface) is missing, the program will show a usage message and exit.



Packet Capturing and Handling: Using libpcap to capture packets and process them.
Data Structures: Managing connections and their statistics.
Display Logic: Using ncurses to display the top 10 connections in real-time.
Sorting Mechanism: Sorting connections based on bytes or packets.
Signal Handling: Gracefully handling program termination (e.g., Ctrl+C).
Memory Management: Ensuring all dynamically allocated memory is properly freed.