#include <assert.h>
#include <stdio.h>

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
	UINT32 from, to;
	UINT16 fromport, toport;
	HANDLE h;

	{
		BOOL ret = WinDivertHelperParseIPv4Address(MASKADDR_FROM, &from);
		assert(ret);
		ret = WinDivertHelperParseIPv4Address(MASKADDR_TO, &to);
		assert(ret);
	}

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
	if (h == INVALID_HANDLE_VALUE) {
		printf("WinDivertOpen = %d\n", GetLastError());
		return -1;
	}

	printf("from=%x:%d to=%x:%d\n", from, fromport, to, toport);

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
		)) {
			printf("WinDivertHelperParsePacket => %d\n", GetLastError());
			continue;
		}

		if (!tcphdr || !iphdr) continue;

		printf(
			"src=%x:%d dst=%x:%d\n",
			iphdr->SrcAddr, tcphdr->SrcPort,
			iphdr->DstAddr, tcphdr->DstPort
		);

		if (iphdr->SrcAddr == to && tcphdr->SrcPort == toport) {
			iphdr->SrcAddr = from;
			tcphdr->SrcPort = fromport;
		}

		if (iphdr->DstAddr == from && tcphdr->DstPort == fromport) {
			iphdr->DstAddr = to;
			tcphdr->DstPort = toport;
		}

		printf(
			" -> src=%x:%d dst=%x:%d\n",
			iphdr->SrcAddr, tcphdr->SrcPort,
			iphdr->DstAddr, tcphdr->DstPort
		);

		if (!WinDivertHelperCalcChecksums(packet, plen, &addr, 0)) {
			printf("WinDivertHelperCalcChecksums => %d", GetLastError());
			continue;
		}

		if (!WinDivertSend(
			h, packet, plen, NULL, &addr
		)) printf("WinDivertSend => %d\n", GetLastError());
	}

	return 1;
}
