FROM = 192.0.2.1
FROMPORT = 443
TO = 198.51.100.2
TOPORT = 4433

all: maskaddr.exe

.PHONY: all zip

# pass the path to unpacked archive here
WINDIVERT = WinDivert-2.2.0-A

CC = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -I$(WINDIVERT)/include \
	-DMASKADDR_FROM='"$(FROM)"' -DMASKADDR_FROM_PORT=$(FROMPORT) \
	-DMASKADDR_TO='"$(TO)"' -DMASKADDR_TO_PORT=$(TOPORT)

LDFLAGS = -L$(WINDIVERT)/x86 -l:WinDivert.dll

maskaddr.exe: maskaddr.o service.o
	$(CC) $(LDFLAGS) -o $@ $^

zip: maskaddr.zip

maskaddr.zip: maskaddr.exe $(WINDIVERT)/x86/WinDivert.dll \
	$(WINDIVERT)/x86/WinDivert32.sys $(WINDIVERT)/x86/WinDivert64.sys
	zip -j $@ $^
