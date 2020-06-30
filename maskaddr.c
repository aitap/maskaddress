#include <assert.h>

#include "windivert.h"

/*
 * The filter will look for packets with destination = "from" and replace it with
 * "to". The filter will also replace source = "to" with "from" to make sure that
 * replies are handled correctly.
 *
 * The addresses have to be string literals, while the ports have to be integer
 * literals. Set them here or on the compiler command line. Addresses specified
 * here belong to TEST-NET subnets reserved for documentation and examples.
 */

#ifndef MASKADDR_FROM
	#define MASKADDR_FROM "192.0.2.1"
#endif

#ifndef MASKADDR_FROM_PORT
	#define MASKADDR_FROM_PORT 443
#endif

#ifndef MASKADDR_TO
	#define MASKADDR_TO "198.51.100.2"
#endif

#ifndef MASKADDR_TO_PORT
	#define MASKADDR_TO_PORT 4433
#endif

static UINT8 packet[0xffff];
static HANDLE h = INVALID_HANDLE_VALUE;

/*
 * We'll have to use the quote trick to place integer literals into string
 * literals for the filter.
 */
#define quote_(x) #x
#define quote(x) quote_(x)

void stop_maskaddr() {
	WinDivertShutdown(h, WINDIVERT_SHUTDOWN_BOTH);
}

int do_maskaddr() {
	UINT32 from, to;
	UINT16 fromport, toport;

	{
		/*
		 * We need the 32-bit representation of the address in order to patch
		 * the packets, so obtain it here. The addresses are compile-time
		 * constants, so we trust the person compiling this to set them
		 * correctly, or crash.
		 */
		BOOL ret = WinDivertHelperParseIPv4Address(MASKADDR_FROM, &from);
		assert(ret);
		ret = WinDivertHelperParseIPv4Address(MASKADDR_TO, &to);
		assert(ret);
	}

	/*
	 * The numbers are in host byte order. Translate them into network byte
	 * order to match and patch.
	 */
	from = WinDivertHelperHtonl(from);
	fromport = WinDivertHelperHtons(MASKADDR_FROM_PORT);
	to = WinDivertHelperHtonl(to);
	toport = WinDivertHelperHtons(MASKADDR_TO_PORT);

	h = WinDivertOpen(
		"("
			"ip.SrcAddr == " MASKADDR_TO
			" && tcp.SrcPort == " quote(MASKADDR_TO_PORT)
		") || ("
			"ip.DstAddr == " MASKADDR_FROM
			" && tcp.DstPort == " quote(MASKADDR_FROM_PORT)
		")",
		WINDIVERT_LAYER_NETWORK,
		0, 0
	);
	if (h == INVALID_HANDLE_VALUE)
		return GetLastError();

	for (;;) {
		UINT plen;
		WINDIVERT_ADDRESS addr;
		PWINDIVERT_IPHDR iphdr;
		PWINDIVERT_TCPHDR tcphdr;

		if (!WinDivertRecv(h, packet, sizeof packet, &plen, &addr)) {
			/*
			 * stop_maskaddr() may be called from a different thread to abort
			 * the process.
			 */
			if (GetLastError() == ERROR_NO_DATA) break;
			else continue;
		}

		if (!WinDivertHelperParsePacket(
			packet, plen, &iphdr, NULL, NULL, NULL,
			NULL, &tcphdr, NULL, NULL, NULL, NULL, NULL
		)) continue;

		if (!tcphdr || !iphdr) continue;

		/* The actual patching logic of the program. */
		if (iphdr->SrcAddr == to && tcphdr->SrcPort == toport) {
			iphdr->SrcAddr = from;
			tcphdr->SrcPort = fromport;
		}

		if (iphdr->DstAddr == from && tcphdr->DstPort == fromport) {
			iphdr->DstAddr = to;
			tcphdr->DstPort = toport;
		}

		/* Required after modifying the packets */
		if (!WinDivertHelperCalcChecksums(packet, plen, &addr, 0))
			continue;

		WinDivertSend(h, packet, plen, NULL, &addr);
	}

	WinDivertClose(h);
	return 0;
}
