#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include<stdint.h>
#include <Winsock2.h>
// need link with Ws2_32.lib
#pragma comment(lib,"ws2_32.lib")

#include<pcap.h>
#pragma comment(lib,"wpcap.lib")

#include<memory.h>
#include <stdlib.h>
#include <sys/types.h>
#include "data.h"
#include <windows.h> 

#include<atlbase.h>
#include<atlconv.h>
#include"iphlpapi.h"
#pragma comment(lib, "Iphlpapi.lib")


uint8_t BroadcastAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // �㲥MAC��ַ,Broadcast

const uint8_t MultcastAddr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }; // �ಥMAC��ַ,neareast
typedef enum { REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10 } EAP_Code;
typedef enum { IDENTITY = 1, NOTIFICATION = 2, MD5 = 4, AVAILABLE = 20 } EAP_Type;
static int times = 20;//�ظ�����Ĵ���

typedef struct setting
{
	char device[100];
	uint8_t	mac[6];
}Setting;

void SendStartPkt(pcap_t *handle, uint8_t localmac[6]);
void GetMacFromDevice(uint8_t mac[6], const char *devicename);
int GetNameMacfromDevice(uint8_t mac[6], char devicename[100]);
void SendResponseIdentity(pcap_t *adhandle, const  u_char *pkt_data, uint8_t localmac[6]);
void SendResponseMD5(pcap_t *adhandle, const  u_char *pkt_data);
long file_size(char *filename);
/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler1(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ether_header *eh;
	x802_header *uh;
	eap_header *eaph;
	time_t local_tv_sec;

	//eap����
	u_char version;//802.1x�汾��
	u_char type;//eap������0--eap,1--eapol
	u_short len;//eap���ݰ�����,�����ײ�
	int i = 0;

	u_char code;//request--1,respond--2
	u_char id;//����id
	u_char eap_type;//1--identity,--md5-challenge,3--legacy_Nak

	//����ַת��Ϊ���ӽṹ
	unsigned char   eh_dst[6] = {0}; //Ŀ�ĵ�ַ
	unsigned char   eh_src[6] = {0}; //Դ��ַ

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* ��ӡ���ݰ���ʱ����ͳ��� */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* ���ehernet���ݰ�ͷ����λ�� */
	eh = (ether_header *)(pkt_data); //��̫��ͷ������

	/* ���802.1x�ײ���λ�� */
	uh = (x802_header *)(pkt_data + 14);

	//ethernetͷ����Ϣ
	for (i = 0; i < 6; i++)
	{
		eh_dst[i] = eh->eh_dst[i];
		eh_src[i] = eh->eh_src[i];
	}
	
	//802.1xͷ����Ϣ
	version = uh->version;
	type = uh->type;
	len = htons(uh->len);//��Ҫ���д��С��ת��

	if (type == 0)
	{
		/* ��ȡeap�ײ�λ�� */
		eaph = (eap_header *)((u_char *)uh + 4);
		code = eaph->code;
		id = eaph->id;
		eap_type = eaph->type;
	}
	
	/* ��ӡMac��ַ��eap��Ϣ */
	for (i = 0; i < 6; i++)
	{
		if (i==5)
			printf("%x", eh_src[i]);
		else
			printf("%x:", eh_src[i]);
	}
	printf("-->");
	for (i = 0; i < 6; i++)
	{
		if (i == 5)
			printf("%x", eh_dst[i]);
		else
			printf("%x:", eh_dst[i]);
	}
	
	printf("\n802.1x:version=%d,type=%d,length=%d\n", version, type, len);
	if (type==0)
		printf("EAP:code=%d,ID=%d,Type=%d\n", code, id, eap_type);
}

int receive802package(){

	pcap_if_t *alldevs;
	pcap_if_t *d;

	int inum;
	int i = 0;

	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;

	char packet_filter[] = "ether proto 0x888e";
	struct bpf_program fcode;

	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
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
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* �������� */
	if ((adhandle = pcap_open(d->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ���
		// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 0, packet_handler1, NULL);

	return 0;
}
/*���漰ether�豸δ���д���,�������ߺ���,�������ô���*/
int auth802x()
{

	//pcap_if_t *alldevs;
	//pcap_if_t *d;
	//int inum;
	int i = 0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	//ʱ�����
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	//ץȥ���
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_short len;

	//�������
	//uint8_t	MAC[6];
	//char devicename[100];
	//uint8_t	MAC[6];
	Setting setting;
	
	struct bpf_program fcode;
	char	FilterStr[100];
	bool serverIsFound = false;

	FILE *fp;
	


	long filesize = file_size("setting.ini");
	if (filesize>0)
	{
		fp = fopen("setting.ini", "rb");
		//-------------------OK-----------------------
		//fscanf(fp, "%s\n", dev1.devicename1);
		//fscanf(fp, "%x\t%x\t%x\t%x\t%x\t%x", dev1.MAC1, dev1.MAC1 + 1, dev1.MAC1 + 2, dev1.MAC1 + 3, 
		//	dev1.MAC1 + 4, dev1.MAC1 + 5);
		//------------------OK------------------------
		fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", setting.device, setting.mac, setting.mac + 1, setting.mac + 2, setting.mac + 3,
			setting.mac + 4, setting.mac + 5);
		//------------------BAD--------------------
		//scanf("%x\t%x\t%x\t%x\t%x\t%x", &devicename, &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
		//fscanf(fp, "%s\n", &dev1.devicename1);
		//fscanf(stdin, "%s\n%x\t%x\t%x\t%x\t%x\t%x", dev1.devicename1, &dev1.MAC1[0], &dev1.MAC1[1], &dev1.MAC1[2], &dev1.MAC1[3], dev1.MAC1[4], &dev1.MAC1[5]);
		//------------------BAD-------------------
		//fscanf(fp,"%s\n%x\t%x\t%x\t%x\t%x\t%x", &devicename, &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
		//fscanf(fp, "%s%x%x%x%x%x%x", devicename, &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
		//-----------------BAD----------------
		//fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", devicename, MAC, MAC+1, MAC+2, MAC+3, MAC+4, MAC+5);
		//----------------BAD-------------
		//fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", &devicename, MAC, MAC + 1, MAC + 2, MAC + 3, MAC + 4, MAC + 5);
		//------------------BAD---------------
		//fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", &devicename, &MAC, MAC + 1, MAC + 2, MAC + 3, MAC + 4, MAC + 5);


		printf("\n");
		
		printf("AdapterName:\t%s\n", setting.device);
		printf("AdapterAddr:\t");
		for (i = 0; i < 6; i++){
			printf("%02X%c", setting.mac[i], i == 6 - 1 ? '\n' : '-');
		}
		
		/*
		printf("AdapterName:\t%s\n", devicename);
		printf("AdapterAddr:\t");
		for (i = 0; i < 6; i++){
			printf("%02X%c", MAC[i], i == 6 - 1 ? '\n' : '-');
		}
		*/
	}
	else
	{
		//-----------------------------------------------------------------------------------------------
		fp = fopen("setting.ini", "wb");
		/* ��ѯ����MAC��ַ */
		if (GetNameMacfromDevice(setting.mac, setting.device) == -1)
			exit(-1);

		printf("AdapterName:\t%s\n", setting.device);

		printf("AdapterAddr:\t");
		for (i = 0; i < 6; i++){
			printf("%02X%c", setting.mac[i], i == 6 - 1 ? '\n' : '-');
		}

		fprintf(fp, "%s\n%2x\t%2x\t%2x\t%2x\t%2x\t%2x", setting.device, setting.mac[0], setting.mac[1], 
			setting.mac[2], setting.mac[3], setting.mac[4], setting.mac[5]);
	}
	fclose(fp);
	printf("debug:%d\n", file_size("setting.ini"));
	//------------------------------------------------------------------------------
	/* ���豸 */
	if ((adhandle = pcap_open(setting.device,          // �豸��
		65536,            // Ҫ��׽�����ݰ��Ĳ��� 
		// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", setting.device);
		/* �ͷ����б� */
		//pcap_freealldevs(alldevs);
		return -1;
	}

	//printf("\nlistening on %s...\n", d->description);

	//----------------------------------------------------------------------------
	
	

	//������������eap���ݰ�
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
		setting.mac[0], setting.mac[1], setting.mac[2], setting.mac[3], setting.mac[4], setting.mac[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);
	/* ����������֤�Ự */
	SendStartPkt(adhandle, setting.mac);
	printf("client: Start.\n");
	//------------------------------------------------------------------
	while (!serverIsFound )
	{
		res = pcap_next_ex(adhandle, &header, &pkt_data);
		// NOTE: ����û�м�������Ƿ�Ӵ��������ѱ�����,�Ѵ���
		if (res == -1)
		  return -1;

		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		//dprintf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

		//printf("\n----%d-----\n", res);
		if (res==1 && pkt_data[18] == 1)
		{
			serverIsFound = true;
			len = *(u_short *)(pkt_data + 20);
			len = htons(len);
			//dprintf("\nServer( %02x:%02x:%02x:%02x:%02x:%02x )-->(%02x:%02x:%02x:%02x:%02x:%02x)\neap_id=%d,len=%d\n", 
			//	pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11], 
			//	pkt_data[0], pkt_data[1], pkt_data[2], pkt_data[3], pkt_data[4], pkt_data[5], pkt_data[19], len);
		}
		else
		{	// ��ʱ������
			if (1 == times)
			{
				printf("\nReconnection is failed.\n");
				return -1;
			}
			printf(",");
			Sleep(1000);
			SendStartPkt(adhandle, setting.mac);
			times--;
			// NOTE: ����û�м�������Ƿ�Ӵ��������ѱ�����
		}
		
	}
	//-----------------------------------------------------------------------
	// �����Ӧ����һ����

	res = pcap_next_ex(adhandle, &header, &pkt_data);
	// NOTE: ����û�м�������Ƿ�Ӵ��������ѱ�����,�Ѵ���
	if (res == -1)
		return -1;
	if (pkt_data[22] == 1)
	{	// ͨ��������յ���Request Identity��Ӧ�ش�Response Identity
		printf("\n[%d] Server: Request Identity!\n", pkt_data[19]);//��ӡID
		SendResponseIdentity(adhandle, pkt_data, setting.mac);
		printf("[%d] client: Response Identity.\n", pkt_data[19]);
	}

	// �����������ֻ����Ϊ802.1X��֤�豸�����İ��������ಥRequest Identity / Request AVAILABLE��
	sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
		pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11]);
	//printf("%s", FilterStr);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);

	//------------------------------------------------------------------------
	times = 30;//�������������
	// ����ѭ����,���ϴ�����֤����
	for (;;)
	{
		// ����pcap_next_ex()�����������ݰ�
		//-------------------------------------------����ȴ��׶�----------
		while ((res = pcap_next_ex(adhandle, &header, &pkt_data) )!= 1)
		{
			printf("."); // ������ʧ�ܻ������ݣ����1�������
			Sleep(1000);     // ֱ���ɹ�����һ�����ݰ���������
			// NOTE: ����û�м�������Ƿ��ѱ����»��ڽӴ�����,�Ѵ���
			if (res == -1){
				printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
				return -1;
			}
		}
		//-------------------------------------------------------------------

		// �����յ���Request���ظ���Ӧ��Response��
		if (pkt_data[18] == REQUEST)
		{
			switch ((EAP_Type)pkt_data[22])
			{
			case IDENTITY:
				printf("\n[%d] Server: Request Identity!\n", pkt_data[19]);
				SendResponseIdentity(adhandle, pkt_data, setting.mac);
				printf("\n[%d] client: Response Identity.\n", pkt_data[19]);
				break;
			case MD5:
				printf("\n[%d] Server: Request MD5-Challenge!\n", pkt_data[19]);
				SendResponseMD5(adhandle, pkt_data);
				printf("\n[%d] client: Response MD5-Challenge.\n", pkt_data[19]);
				break;
			default:
				printf("\n[%d] Server: Request (type:%d)!\n", pkt_data[19], (EAP_Type)pkt_data[22]);
				printf("Error! Unexpected request type\n");
				exit(-1);
				break;
			}
			//break;//�˳�forѭ��
		}
		else if ((EAP_Code)pkt_data[18] == FAILURE)
		{	// ������֤ʧ����Ϣ
			printf("\n[%d] Server: Failure.\n", pkt_data[19]);
			if (1 == times)
			{
				printf("Reconnection is failed.---from Forward @SCUT\n");
				return -1;
			}
			//������֤��ʼ
			Sleep(1000);
			SendStartPkt(adhandle, setting.mac);
			times--;
			//break;
		}
		else if ((EAP_Code)pkt_data[18] == SUCCESS)
		{
			printf("\n[%d] Server: Success.\n", pkt_data[19]);
			// ˢ��IP��ַ
			times = 20;
			//break;
		}
		else
		{
			printf("\n[%d] Server: (H3C data)\n", pkt_data[19]);
			// TODO: ����û�д���Ϊ�Զ������ݰ�
			break;
		}
	}

	return 0;
}
void SendStartPkt(pcap_t *handle, uint8_t localmac[6])
{
	uint8_t packet[19] = {0};//ע���ʼ��Ϊ0
	//���ether����ͷ
	ether_header *eh = (ether_header *)packet;
	x802_header *uh = (x802_header *)(packet + sizeof(ether_header));
	uint8_t *sp = (uint8_t *)(packet + sizeof(ether_header)+sizeof(x802_header));

	int i = 0;
	for (i = 0; i < 6; i++)
	{
		eh->eh_src[i] = localmac[i];
		eh->eh_dst[i] = MultcastAddr[i];
	}
	eh->eh_type = htons(0x888e);
	
	uh->version = 0x01;
	uh->type = 0x01;
	uh->len = 0x0;
	*sp = 0x0;

	if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0){
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return;
	}
}
//�յ�server ���͵�requestʱ����
void SendResponseIdentity(pcap_t *adhandle, const u_char *pkt_data, uint8_t localmac[6])
{
	//printf("eap struct len:%d\n",sizeof(eap_header));
	u_char packet[100] = { 0 };
	ether_header *eth = (ether_header *)packet;
	x802_header *uh = (x802_header *)(packet+14);//14=sizeof(eher_header)
	eap_header *eh = (eap_header *)(packet+sizeof(ether_header)+sizeof(x802_header));

	const char *IDENTITY = "host/billgates-PC";
	u_short lens;
	//printf("ether:%d,x802:%d,eap:%d����λ��:%d", sizeof(ether_header),sizeof(x802_header),sizeof(eap_header)
	//	,sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header)-1);
	//u_short datapos = sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header)-1;
	u_char *identity = (u_char *)(packet + sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header)-1);//��eap���ϵͳ��0��ʼ
	//��ʼ��etherheader
	int i = 0;
	/*sucess֮��,scutclientά�����ӵĻظ��ǹ̶���,Ŀ�ĵ��ǹ㲥��ַ,Դ��ַ����Mac.
	����򵥽������ݰ���̫����ַ���лظ�,����Ļظ�Ҳ����ͨ��,��Ч�ʸ���
	*/
	for (i = 0; i < 6; i++){
		//eth->eh_src[i] = pkt_data[i];//dst
		//eth->eh_dst[i] = pkt_data[i + 6];//src
		eth->eh_src[i] = localmac[i];//dst
		eth->eh_dst[i] = MultcastAddr[i];//src
	}
	eth->eh_type = htons(0x888e);

	//��ʼ��x802_header
	uh->version = 0x01;
	uh->type = 0x0;
	uh->len = 0x0;
	
	//��ʼ��eap_header
	eh->code = 0x02;//respond
	eh->id = pkt_data[19];
	eh->len = 0x0;
	eh->type = 0x01;//identity

	//��ʼidentity��Ϣ
	//*identity = "aaa";
	//printf("\nLen('%s')=%d\n",IDENTITY, strlen(IDENTITY));
	memcpy(identity, IDENTITY, strlen(IDENTITY));

	//lensΪeap��ͷ+������ݴ�С
	lens = sizeof(eap_header)-1+strlen(IDENTITY);
	//printf("\neap+�����ܳ���:%d\n",lens);
	uh->len = htons(lens);
	eh->len = uh->len;
	//printf("\n�ܴ�С:%d\n,������:%d\n", sizeof(packet), sizeof(ether_header)+sizeof(x802_header)+lens);
	//ֻ����packet����������ǲ���,���ಿ�ֲ��ܷ���
	if (pcap_sendpacket(adhandle, packet, sizeof(ether_header)+sizeof(x802_header)+lens) != 0){//������-1
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
		return;
	}
}
void SendResponseMD5(pcap_t *adhandle, const  u_char *pkt_data){
	u_char packet[100] = { 0 };
	ether_header *eth = (ether_header *)packet;
	x802_header *uh = (x802_header *)(packet + 14);//14=sizeof(eher_header)
	eap_header *eh = (eap_header *)(packet + sizeof(ether_header)+sizeof(x802_header));

	u_short lens;
	u_short datapos;

	//��ʼ��etherheader
	int i = 0;
	for (i = 0; i < 6; i++){
		eth->eh_src[i] = pkt_data[i];//dst
		eth->eh_dst[i] = pkt_data[i + 6];//src
	}
	eth->eh_type = htons(0x888e);

	//��ʼ��x802_header
	uh->version = 0x01;
	uh->type = 0x0;
	uh->len = 0x0;

	//��ʼ��eap_header
	eh->code = 0x02;//respond
	eh->id = pkt_data[19];
	eh->len = 0x0;
	eh->type = 0x03;//Legacy Nak

	//������Ϣ
	datapos = sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header);
	//printf("\n���ݵ���ʼλ��:%d\n",datapos);
	packet[datapos-1] = 0x20;//���ֵ���������,0x19--peap

	//lensΪeap��ͷ+������ݴ�С
	lens = sizeof(eap_header)-1 + 1;
	//printf("\neap+�����ܳ���:%d\n", lens);
	uh->len = htons(lens);
	eh->len = uh->len;
	//printf("\n�ܴ�С:%d\n,������:%d\n", sizeof(packet), sizeof(ether_header)+sizeof(x802_header)+lens);
	//ֻ����packet����������ǲ���,���ಿ�ֲ��ܷ���
	if (pcap_sendpacket(adhandle, packet, sizeof(ether_header)+sizeof(x802_header)+lens) != 0){//������-1
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
		return;
	}
}
/*linux �º���,�뿴linux�³���*/
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{
	//Ҫʹ�ñ�����mac
	mac[0] = 0x7c;
	mac[1] = 0x05;
	mac[2] = 0x07;
	mac[3] = 0x40;
	mac[4] = 0x82;
	mac[5] = 0xe6;
}
/*windows �º���*/
int GetNameMacfromDevice(uint8_t mac[6], char devicename[100])
{
	u_int inum;
	u_int i = 0, j = 0;
	char *name;
	//char tmp[100];

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);


	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS)
	{
		GlobalFree(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			//if (strstr(pAdapter->Description, "PCI") > 0 || pAdapter->Type == 71)
			//pAdapter->Description�а���"PCI"Ϊ����������,pAdapter->Type��71Ϊ����������
			//{
			printf("---------------------------%d---------------------------------\n", j + 1);
			printf("AdapterName:\t%s\n", pAdapter->AdapterName);
			printf("AdapterDesc:\t%s\n", pAdapter->Description);

			printf("AdapterAddr:\t");
			for (i = 0; i < pAdapter->AddressLength; i++)
			{
				printf("%02X%c", pAdapter->Address[i],
					i == pAdapter->AddressLength - 1 ? '\n' : '-');
			}
			printf("AdapterType:\t%d\n", pAdapter->Type);
			printf("IPAddress:\t%s\n", pAdapter->IpAddressList.IpAddress.String);
			printf("IPMask:\t%s\n", pAdapter->IpAddressList.IpMask.String);
			//}
			pAdapter = pAdapter->Next;
			j++;
		}

		printf("Enter the interface number (1-%d):", j);
		scanf("%d", &inum);

		if (inum < 1 || inum > j)
		{
			printf("\nInterface number out of range.\n");
			return -1;
		}
		/* ��ת����ѡ�е������� */
		for (pAdapter = pAdapterInfo, i = 0; i < inum - 1; pAdapter = pAdapter->Next, i++);

		name = pAdapter->AdapterName;
		/*ת��Ϊwinpcap���豸��*/
		strcpy(devicename, "rpcap://\\Device\\NPF_");
		strcpy(devicename + strlen("rpcap://\\Device\\NPF_"), name);

		//printf("�ڲ�:%s\n", devicename);

		for (i = 0; i < pAdapter->AddressLength; i++)
		{
			mac[i] = pAdapter->Address[i];
		}
		return 0;
	}
	else
	{
		printf("Call to GetAdaptersInfo failed.\n");
		return -1;
	}
	return 0;
}
/*�ʺ�С�ļ��жϴ�С*/
long file_size(char *filename)
{
	long filesize = -1;
	FILE *fp;
	fp = fopen(filename, "rb");
	if (fp == NULL)
		return filesize;
	
	fseek(fp,0,SEEK_END);
	filesize = ftell(fp);
	fclose(fp);
	return filesize;
}