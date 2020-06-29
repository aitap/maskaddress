# pass the path to unpacked archive here
WINDIVERT = WinDivert-2.2.0-A

CC = i686-w64-mingw32-gcc
CFLAGS = -I$(WINDIVERT)/include
LDFLAGS = -L$(WINDIVERT)/x86 -l:WinDivert.dll -mwindows

maskaddr.exe: maskaddr.o
	$(CC) $(LDFLAGS) -o $@ $^
