#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "windivert.h"
#define MAXURL 4096


typedef struct
{
	char *domain;
	char *uri;
} URL, *PURL;


#define MAXBUF 1500
void CheckURL(char *http) {
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	UINT16 i = 0,j=0;
	URL url = { domain, uri };
	//printf("%c %c\n", http[0], http[1]);
	//system("pause");
	if (strncmp(http, get_str, sizeof(get_str) - 1) == 0)
	{
		i += sizeof(get_str) - 1;
	}
	else if (strncmp(http, post_str, sizeof(post_str) - 1) == 0)
	{
		i += sizeof(post_str) - 1;
	}
	else
	{
		return FALSE;
	}
	for (j = 0;  http[i] != ' '; j++, i++)
	{
		uri[j] = http[i];
	}
	uri[j] = '\0';

	if (strncmp(http + i, http_host_str, sizeof(http_host_str) - 1) != 0)
	{
		return FALSE;
	}
	i += sizeof(http_host_str) - 1;
	
	for (j = 0; http[i] != '\r'; j++, i++)
	{
		domain[j] = http[i];
	}
	if (j == 0)
	{
		return FALSE;
	}
	if (domain[j - 1] == '.')
	{
		j--;
		if (j == 0)
		{
			return FALSE;
		}
	}
	domain[j] = '\0';
	printf("URL %s: \n", domain);
	//printf("URL %s/%s: \n", domain, uri);

}

int main() {
	HANDLE handle;
	WINDIVERT_ADDRESS addr; // Packet address
	unsigned char packet[MAXBUF];    // Packet buffer
	unsigned char *http;
	UINT packetLen;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	

	handle = WinDivertOpen(
		"ip && "                    // Only IPv4 supported
		"(tcp.DstPort == 80 || tcp.SrcPort == 80) && "     // HTTP (port 80) 
		"tcp.PayloadLength > 0",    // TCP data packets only
		0, 0, 0
	);

	if (handle == INVALID_HANDLE_VALUE) { //windivert open error
		printf("%d\n", GetLastError());
		exit(1);

	}

	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen))
		{
			// Handle recv error
			continue;
		}
		
		// receive packet

		ip_header = &packet;
		tcp_header = (char *)ip_header + (int)(ip_header->HdrLength *4) ;
		http = (char *)tcp_header + (int)tcp_header->HdrLength * 4;
		//printf("%s\n", http);
		
		//printf("%d\n",tcp_header->DstPort);
		
		// http ?
		// HTTP/1.1

		CheckURL(http);






		// Modify packet.

		if (!WinDivertSend(handle, packet, packetLen, &addr, NULL))
		{
			// Handle send error
			continue;
		}
	}


}

