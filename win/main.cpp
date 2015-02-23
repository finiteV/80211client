#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include<stdint.h>
#include <Winsock2.h>
// need link with Ws2_32.lib
#pragma comment(lib,"ws2_32.lib")

#include<pcap.h>
#pragma comment(lib,"wpcap.lib")
//#include "remote-ext.h"

/*·ÅÖÃÒ»¸ö¿âËÑË÷¼ÇÂ¼µ½¶ÔÏóÎÄ¼þÖÐ£¬Õâ¸öÀàÐÍÓ¦¸ÃÊÇºÍcommentstring
£¨Ö¸¶¨ÄãÒªLinkerËÑË÷µÄlibµÄÃû³ÆºÍÂ·¾¶£©Õâ¸ö¿âµÄÃû×Ö·ÅÔÚObjectÎÄ¼þµÄ
Ä¬ÈÏ¿âËÑË÷¼ÇÂ¼µÄºóÃæ£¬linkerËÑË÷Õâ¸ö¿â¾ÍÏñÄãÔÚÃüÁîÐÐÊäÈëÕâ¸öÃüÁîÒ»Ñù¡£
Äã¿ÉÒÔÔÚÒ»¸öÔ´ÎÄ¼þÖÐÉèÖÃ¶à¸ö¿â¼ÇÂ¼£¬ËüÃÇÔÚobjectÎÄ¼þÖÐµÄË³ÐòºÍÔÚÔ´ÎÄ
¼þÖÐµÄË³ÐòÒ»Ñù¡£Èç¹ûÄ¬ÈÏ¿âºÍ¸½¼Ó¿âµÄ´ÎÐòÊÇÐèÒªÇø±ðµÄ£¬Ê¹ÓÃZ±àÒë¿ª¹ØÊÇ·ÀÖ¹Ä¬ÈÏ¿â·Åµ½objectÄ£¿é¡£
*/
#include<memory.h>

#include <stdlib.h>
#include <sys/types.h>
#include "data.h"



unsigned short checksum(unsigned short *addr, int len);
int sendpackage();//·¢ËÍTCPÊý¾Ý°ü
int receivepackage();
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int receive802package();
void SendStartPkt(pcap_t *handle, uint8_t localmac[]);
int auth802x();

int main(int argc, char *argv[])
{
	//sendpackage();
	
	//receivepackage();
	//receive802package();
	
	
	int res;
	res = auth802x();

	system("pause");
	if (res < 0)
		return res;
	return 0;
}


int receivepackage(){

	pcap_if_t *alldevs;
	pcap_if_t *d;

	int inum;
	int i = 0;

	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;

	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	/* »ñµÃÉè±¸ÁÐ±í */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ´òÓ¡ÁÐ±í */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* ÊÍ·ÅÉè±¸ÁÐ±í */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Ìø×ªµ½ÒÑÑ¡Éè±¸ */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* ´ò¿ªÊÊÅäÆ÷ */
	if ((adhandle = pcap_open(d->name,  // Éè±¸Ãû
		65536,     // Òª²¶×½µÄÊý¾Ý°üµÄ²¿·Ö
		// 65535±£Ö¤ÄÜ²¶»ñµ½²»Í¬Êý¾ÝÁ´Â·²ãÉÏµÄÃ¿¸öÊý¾Ý°üµÄÈ«²¿ÄÚÈÝ
		PCAP_OPENFLAG_PROMISCUOUS,         // »ìÔÓÄ£Ê½
		1000,      // ¶ÁÈ¡³¬Ê±Ê±¼ä
		NULL,      // Ô¶³Ì»úÆ÷ÑéÖ¤
		errbuf     // ´íÎó»º³å³Ø
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* ÊÍ·ÅÉè±¸ÁÐ±í */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ¼ì²éÊý¾ÝÁ´Â·²ã£¬ÎªÁË¼òµ¥£¬ÎÒÃÇÖ»¿¼ÂÇÒÔÌ«Íø */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* ÊÍ·ÅÉè±¸ÁÐ±í */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* »ñµÃ½Ó¿ÚµÚÒ»¸öµØÖ·µÄÑÚÂë */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* Èç¹û½Ó¿ÚÃ»ÓÐµØÖ·£¬ÄÇÃ´ÎÒÃÇ¼ÙÉèÒ»¸öCÀàµÄÑÚÂë */
		netmask = 0xffffff;


	//±àÒë¹ýÂËÆ÷
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* ÊÍ·ÅÉè±¸ÁÐ±í */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//ÉèÖÃ¹ýÂËÆ÷
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* ÊÍ·ÅÉè±¸ÁÐ±í */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* ÊÍ·ÅÉè±¸ÁÐ±í */
	pcap_freealldevs(alldevs);

	/* ¿ªÊ¼²¶×½ */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* »Øµ÷º¯Êý£¬µ±ÊÕµ½Ã¿Ò»¸öÊý¾Ý°üÊ±»á±»libpcapËùµ÷ÓÃ */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	struct sockaddr_in antelope;
	char *udpsrc;

	/* ½«Ê±¼ä´Á×ª»»³É¿ÉÊ¶±ðµÄ¸ñÊ½ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* ´òÓ¡Êý¾Ý°üµÄÊ±¼ä´ÁºÍ³¤¶È */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* »ñµÃIPÊý¾Ý°üÍ·²¿µÄÎ»ÖÃ */
	ih = (ip_header *)(pkt_data +
		14); //ÒÔÌ«ÍøÍ·²¿³¤¶È

	/* »ñµÃUDPÊ×²¿µÄÎ»ÖÃ */
	ip_len = (ih->h_verlen & 0xf) * 4;//ipÍ·³¤¶È
	uh = (udp_header *)((u_char *)ih + ip_len);

	/* ½«ÍøÂç×Ö½ÚÐòÁÐ×ª»»³ÉÖ÷»ú×Ö½ÚÐòÁÐ */
	sport = ntohs(uh->source);
	dport = ntohs(uh->dest);

	antelope.sin_addr.s_addr = ih->sourceIP; // store IP in antelope
	udpsrc = inet_ntoa(antelope.sin_addr);

	antelope.sin_addr.s_addr = ih->destIP; // store IP in antelope
	//some_addr = inet_ntoa(ih->sourceIP); // return the IP
	/* ´òÓ¡IPµØÖ·ºÍUDP¶Ë¿Ú */
	printf("%s:%d -> %s:%d\n",
		udpsrc,
		sport,
		inet_ntoa(antelope.sin_addr),
		dport);
}

/*
*ÄÑ¶È×î´ó¹¹½¨Êý¾Ý°ü
*/
int sendpackage()
{
	/***********Éè±¸*****************/
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	int inum;//Ñ¡ÔñÍøÂçÉè±¸
	char errbuf[PCAP_ERRBUF_SIZE];

	//Êä³öÉè±¸¾ä±ú
//	pcap_t *fp;
	//
	pcap_t *adhandle;
	/****************************/
	
	/************Êý¾Ý°ü¹¹Ôì************************/
	//´ý·¢ËÍÊý¾Ý
	unsigned char buffer[IPTCPSIZE] = { 0 };

	//ÒÔÌ«ÍøÊ×²¿Ö¸Õë
	ether_header *pether_header = (ether_header *)buffer;
	//IPÊý¾ÝÍ·Ö¸Õë
	ip_header *pip_herder = (ip_header *)(buffer + sizeof(ether_header));
	//UDPÊý¾ÝÍ·Ö¸Õë
	//udp_header *pudp_herder = (udp_header *)(buffer + sizeof(ether_header)+sizeof(ip_header));
	tcp_header *ptcp_header = (tcp_header *)(buffer + sizeof(ether_header)+sizeof(ip_header));
	//Î±Ê×²¿Í·Ö¸Õë
	char buffer2[sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header)+sizeof(psd_header)] = { 0 };
	psd_header *psd = (psd_header *)buffer2;
	/****************************/

	//Õë¶ÔÒÔÌ«ÍøÍ·²¿Ô´µØÖ·½øÐÐ¸³Öµ
	pether_header->eh_dst[0] = 0x00;		//0x0 * 16 + 0x0;;		°Ù¶È00:1a:a9:15:46:57
	pether_header->eh_dst[1] = 0x1a;		//0x2 * 16 + 0x1;		
	pether_header->eh_dst[2] = 0xa9;		//0x2 * 16 + 0x7;
	pether_header->eh_dst[3] = 0x15;		//0x2 * 16 + 0x3;
	pether_header->eh_dst[4] = 0x46;		//0x7 * 16 + 0x2;
	pether_header->eh_dst[5] = 0x57;		//0xf * 16 + 0xe;
	//Õë¶ÔÒÔÌ«ÍøÍ·²¿Ä¿µÄµØÖ·½øÐÐ¸³Öµ
	pether_header->eh_src[0] = 0x78;		//0x0 * 16 + 0x0;;		±¾»ú78:84:3c:d0:34:6a
	pether_header->eh_src[1] = 0x84;		//0x1 * 16 + 0xF;
	pether_header->eh_src[2] = 0x3c;		//0xD * 16 + 0x0;
	pether_header->eh_src[3] = 0xd0;		//0x1 * 16 + 0x6;
	pether_header->eh_src[4] = 0x34;		//0x6 * 16 + 0x3;
	pether_header->eh_src[5] = 0x6a;		//0x7 * 16 + 0x1;
	//Õë¶ÔÒÔÌ«ÍøÐ­Òé½øÐÐ¸³Öµ
	pether_header->eh_type = htons(0x0800);;//ETHERTYPE_IP

	//¹¹½¨IPÊý¾ÝÍ·
	pip_herder->h_verlen = (4 << 4 | (sizeof(ip_header) / sizeof(ULONG))); //version+ipÍ·²¿³¤¶È£¨°´4×Ö½Ú¶ÔÆë£©
 //  pip_herder->version = 4; //Éè¶¨°æ±¾ºÅ,Ò»°ãIPÀàÐÍÎªIPv4
	pip_herder->tos = 0; //Éè¶¨ÀàÐÍ,·þÎñÀàÐÍ
	//Éè¶¨³¤¶È,×Ü³¤¶È£¨°üº¬IPÊý¾ÝÍ·£¬TCPÊý¾ÝÍ·ÒÔ¼°Êý¾Ý£©
	pip_herder->total_len = htons(sizeof(buffer)-sizeof(ether_header));

	pip_herder->ident = htons(0x1000);//Éè¶¨Ê¶±ðÂë

	pip_herder->frag_and_flags = htons(0);//Éè¶¨Æ«ÒÆÁ¿,±êÖ¾Î»Æ«ÒÆÁ¿
	pip_herder->ttl = 0x80;//Éè¶¨Éú´æÊ±¼ä
	pip_herder->protocol = IPPROTO_TCP; //Éè¶¨Ð­ÒéÀàÐÍ,(6,tcp),Ð­ÒéÀàÐÍ
	pip_herder->checksum = 0; //Éè¶¨¼ìÑéºÍ
	pip_herder->sourceIP = inet_addr("211.66.26.220"); //Éè¶¨Ô´µØÖ·£¬±¾»ú
	pip_herder->destIP = inet_addr("119.75.217.56");//Éè¶¨Ä¿µÄµØÖ·£¬°Ù¶È
	pip_herder->checksum = checksum((uint16_t*)pip_herder, sizeof(ip_header)); //ÖØÐÂÉè¶¨¼ìÑéºÍ
	/*
	//¹¹½¨UDPÊý¾ÝÍ·;
	pudp_herder->dest = htons(7865); //Ä¿µÄ¶Ë¿ÚºÅ
	pudp_herder->source = htons(2834);//Ô´¶Ë¿ÚºÅ
	pudp_herder->len = htons(sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header));//Éè¶¨³¤¶È
	pudp_herder->checkl = 0;//Éè¶¨¼ìÑéºÍ
	*/
	//¹¹½¨TCPÊý¾ÝÍ·
	ptcp_header->th_sport = htons(1234);
	ptcp_header->th_dport = htons(80);
	ptcp_header->th_seq = htonl(0x7d2cb526);
	ptcp_header->th_ack = htonl(0);
	//0000,0000 00,000010
	ptcp_header->th_lenres = ((sizeof(tcp_header) / sizeof(u_long)) << 4 | 0);
	printf("%x\n", ptcp_header->th_lenres);
	ptcp_header->th_flag = 2;
	ptcp_header->th_win = htons(2048);
	ptcp_header->th_sum = 0;
	ptcp_header->th_urp = 0;

	//¹¹ÔìÎ±Ê×²¿
	psd->saddr = inet_addr("211.66.26.220");//±¾»ú
	psd->daddr = inet_addr("119.75.217.56");//°Ù¶È
	psd->ptcl = IPPROTO_TCP;
	psd->tcpl = htons(sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header));
	psd->mbz = 0;

	memcpy(buffer2 + sizeof(psd_header), (void *)ptcp_header, sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header));
	//0x31c7
	ptcp_header->th_sum = checksum((USHORT *)buffer2, sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header)+sizeof(psd_header));
	/*************¹¹ÔìÊý¾Ý°ü½áÊø**********************/
	/* »ñÈ¡±¾µØ»úÆ÷Éè±¸ÁÐ±í */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/*´òÓ¡ÁÐ±í*/
	for (d = alldevs; d; d = d->next){
		printf("%d,%s",++i,d->name);
		if (d->description)
			printf("(%s)\n", d->description);
		else
			printf("(No description available)\n");
	}
	if (i == 0){
		printf("\nNo interfaces found! Make sure WinPcap is installde.\n");
		return -1;
	}

	printf("Enter the interface number(1-%d:)", i);
	scanf("%d",&inum);

	if (inum < 1 || inum > i){
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	/*Ìø×ªµ½ÒÑÑ¡Éè±¸*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* ´ò¿ªÊÊÅäÆ÷ */
	if ((adhandle = pcap_open(d->name,  // Éè±¸Ãû
		65536,     // Òª²¶×½µÄÊý¾Ý°üµÄ²¿·Ö 
						// 65535±£Ö¤ÄÜ²¶»ñµ½²»Í¬Êý¾ÝÁ´Â·²ãÉÏµÄÃ¿¸öÊý¾Ý°üµÄÈ«²¿ÄÚÈÝ
		PCAP_OPENFLAG_PROMISCUOUS,         // »ìÔÓÄ£Ê½
		1000,      // ¶ÁÈ¡³¬Ê±Ê±¼ä
		NULL,      // Ô¶³Ì»úÆ÷ÑéÖ¤
		errbuf     // ´íÎó»º³å³Ø
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* ÊÍ·ÅÉè±¸ÁÐ±í */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ·¢ËÍÊý¾Ý°ü */
	if (pcap_sendpacket(adhandle, buffer, sizeof(buffer) /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adhandle));
		return -1;
	}
	else
		printf("package send\n");

	return 0;
}

//ip.dst==119.75.217.56 || ip.src==119.75.217.56
//¼ÆËãÐ£ÑéºÍ
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size>1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR *)buffer;
	}
	//½«32Î»Êý×ª»»³É16  
	while (cksum >> 16)
		cksum = (cksum >> 16) + (cksum & 0xffff);
	return (USHORT)(~cksum);
}

unsigned short checksum1(unsigned short *addr, int len)
{
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}


	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}


	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}


