typedef struct ether_header
{
	unsigned char   eh_dst[6]; //Ŀ�ĵ�ַ
	unsigned char   eh_src[6]; //Դ��ַ
	unsigned short  eh_type; //eh_type��ֵ��Ҫ������һ���Э�飬���Ϊip��Ϊ0x0800
}ether_header;

typedef struct ip_hdr
{
	unsigned char       h_verlen; //IP����ΪIPv4+ipͷ�����ȣ���4�ֽڶ���)
//	unsigned char       version:4; //һ��IP����ΪIPv4,4��ʾ4λ
	unsigned char       tos; //��������
	unsigned short      total_len; //�ܳ��ȣ�����IP����ͷ��TCP����ͷ�Լ����ݣ�
	unsigned short      ident; //ʶ����,ID���嵥��IP,
	unsigned short      frag_and_flags;//��־λƫ����
	unsigned char       ttl; //����ʱ��
	unsigned char       protocol; //Э������
	unsigned short      checksum; //����
	unsigned long        sourceIP; //ԴIP��ַ
	unsigned long        destIP; //Ŀ��IP��ַ
}ip_header;


typedef struct tcp_header
{
	unsigned short    th_sport;  //Դ�˿�
	unsigned short    th_dport; //Ŀ�Ķ˿�
	unsigned int     th_seq; //���к�
	unsigned int     th_ack; //ȷ�Ϻ�
	//0000,0000 00,000010
	unsigned char    th_lenres; //4 λTCP�ײ�+6λ������ǰ 4 λ
	unsigned char    th_flag; //6λ������ǰ��2 λ+��־λ
	unsigned short    th_win; //���ڴ�С
	unsigned short    th_sum; //�����
	unsigned short    th_urp; //����ָ��
}tcp_header;

typedef struct udp_header
{
	uint16_t source;			 /* source port,�ȼ���unsigned int */
	uint16_t dest;				 /* destination port */
	uint16_t len;					 /* udp length */
	uint16_t checkl;			 /* udp checksum */
}udp_header;

typedef struct psd_header
{
	unsigned long    saddr;  //Դ��ַ
	unsigned long    daddr; //Ŀ�ĵ�ַ
	char            mbz; //�ÿ�
	char            ptcl; //Э������
	unsigned short    tcpl; //���ݰ�����
}psd_header;

#define IPTCPSIZE 58

typedef struct x802_header
{
	u_char version;//802.1x�汾��
	u_char type;//eap������0--eap,1--eapol
	u_short len;//eap���ݰ�����,�����ײ�
}x802_header;

typedef struct eap_header
{
	u_char code;//request--1,respond--2
	u_char id;//����id
	u_short len;//eap���ݰ�����,�����ײ�
	u_char type;//1--identity,--md5-challenge,3--legacy_Nak
}eap_header;//��СΪ6