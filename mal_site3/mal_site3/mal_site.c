#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "windivert.h"
#define MAXURL 4096

typedef struct
{
	char *domain;
	char *uri;
} URL, *Ps;

#define MAXBUF 1500

void CheckURL(char *http, FILE *fp,FILE *fout) {
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	static const char httpuse[]= "http://";
	char domain[MAXURL];
	char uri[MAXURL];
	UINT16 i = 0,j=0,c1,c2,count;
	URL url = { domain, uri };
	char blackurl[100] = { 0, };;
	char *findurl;
	int urllen;
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
	while (!feof(fp)){
		c1 = 0;
		c2 = 0;
		fgets(blackurl, 100, fp);
		if (strncmp(blackurl, "http://", 7) == 0) {//url: http://
			c1 = c1 + 7;
			if (strncmp(blackurl+7, "www.", 4) == 0) { //url: http:// www
				c1 = c1 + 4;
			}
		}
		if (strncmp(blackurl, "www.", 4) == 0) { //url: www
			c1 = c1 + 4;
		}


		if (strncmp(domain, "http://", 7) == 0) {//url: http://
			c2 = c2 + 7;
			if (strncmp(domain+7, "www.",  4) == 0) { //url: http:// www
				c2 = c2 + 4;
			}
		}
		if (strncmp(domain, "www.",  4) == 0) { //url : www
			c2 = c2 + 4;
		}

		count = 0;
		while (1) {
			
			if (blackurl[c1 + count] == NULL) break;
			count++;
		}
		findurl = (char *)malloc(count);
		memset(findurl, 0, count);
		memcpy(findurl, blackurl + c1, count - 1);

		if (strstr(domain, findurl) != NULL) {
			printf("[URL Block] : %s\n", domain);
			fprintf(fout, "%s\n", domain);
		}
		
	}
	fseek(fp, 0, SEEK_SET);
}

int main() {
	HANDLE handle;
	WINDIVERT_ADDRESS addr; // Packet address
	unsigned char packet[MAXBUF];    // Packet buffer
	unsigned char *http;
	UINT packetLen;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	
	FILE *fp,*fout;
	fp = fopen("mal_site.txt", "r");
	fout = fopen("malsite_log.txt", "w");
	if (fp == NULL) {
		fprintf(stderr, "Can't open blacklist file\n");
		exit(1);
	}
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

		CheckURL(http,fp,fout);
	}

	close(fp);
	close(fout);
}

