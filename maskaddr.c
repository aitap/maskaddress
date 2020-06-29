#include <assert.h>

#include "windivert.h"

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

UINT8 packet[0xffff];

#define quote_(x) #x
#define quote(x) quote_(x)

int main() {
	UINT32 src, dest;
	UINT16 srcport, destport;
	HANDLE h;

	{
		BOOL ret = WinDivertHelperParseIPv4Address(MASKADDR_FROM, &src);
		assert(ret);
		ret = WinDivertHelperParseIPv4Address(MASKADDR_TO, &dest);
		assert(ret);
	}

	src = WinDivertHelperHtonl(src);
	srcport = WinDivertHelperHtons(MASKADDR_FROM_PORT);
	dest = WinDivertHelperHtonl(dest);
	destport = WinDivertHelperHtons(MASKADDR_TO_PORT);

	h = WinDivertOpen(
		"("
			"ip.SrcAddr == " MASKADDR_FROM
			" && tcp.SrcPort == " quote(MASKADDR_FROM_PORT)
		")"
		"|| ("
			"ip.DstAddr == " MASKADDR_FROM
			" && tcp.DstPort == " quote(MASKADDR_FROM_PORT)
		")",
		WINDIVERT_LAYER_NETWORK,
		0, 0
	);
	if (h == INVALID_HANDLE_VALUE) return -1;

	for (;;) {
		UINT plen;
		WINDIVERT_ADDRESS addr;
		PWINDIVERT_IPHDR iphdr;
		PWINDIVERT_TCPHDR tcphdr;

		if (!WinDivertRecv(
			h, packet, sizeof packet, &plen, &addr
		)) continue;

		if (!WinDivertHelperParsePacket(
			packet, plen, &iphdr, NULL, NULL, NULL,
			NULL, &tcphdr, NULL, NULL, NULL, NULL, NULL
		)) continue;

		if (!tcphdr || !iphdr) continue;

		if (iphdr->SrcAddr == src && tcphdr->SrcPort == srcport) {
			iphdr->SrcAddr = dest;
			tcphdr->SrcPort = destport;
		}

		if (iphdr->DstAddr == src && tcphdr->DstPort == srcport) {
			iphdr->DstAddr = dest;
			tcphdr->DstPort = destport;
		}

		if (!WinDivertHelperCalcChecksums(packet, plen, &addr, 0))
			continue;

		WinDivertSend(
			h, packet, plen, NULL, &addr
		);
	}

	return 1;
}
