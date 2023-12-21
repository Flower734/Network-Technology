#ifndef ROUTER_H//定义这个头文件
#define ROUTER_H
#endif
#define WIN32
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"
//#include <iostream>
#include<WinSock2.h>
#include <process.h>
#include <stdio.h>
#include <bitset>
#include <time.h>
#include<vector>
#pragma comment(lib,"wpcap.lib")
//#pragma comment(lib, "packet.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define BYTE unsigned char
#define TIMELIMIT 6000

using namespace std;


#pragma pack(1) //一字节对齐

pcap_if_t* Header;
pcap_if_t* currentDevice;
pcap_t* targetDevice;

//存ip和mac地址
char ip[10][20];
char mask[10][20];
BYTE Local_Mac[6];


HANDLE hThread;
DWORD dwThreadId;


/****************************帧的结构体************************************/
typedef struct FrameHeader_t//帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
}FrameHeader_t;

typedef struct IPHeader_t {//IP首部
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
} IPHeader_t;

typedef struct IPFrame_t {//IP 帧
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
} IPFrame_t;

typedef struct ARPFrame_t //APR帧
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;//操作类型
	BYTE SendHa[6];//发送方MAC地址,一个长度为 6 的字节数组
	DWORD SendIP;//发送方IP地址,32位整数
	BYTE RecvHa[6];//接收方MAC地址
	DWORD RecvIP;//接收方IP地址
}ARPFrame_t;

typedef struct ICMPHeader_t {
	BYTE Type;
	BYTE Code;
	WORD Checksum;
	WORD Id;
	WORD Seq;
} ICMPHeader_t;

/***************************** 路由表项和表 *******************************/
class Route_entry
{
//private:
public:
	int index;//索引
	DWORD des_ip;//目标ip地址
	//DWORD src_ip;//源ip地址
	DWORD netmask;//掩码
	DWORD next_hop;
	BYTE nextMac[6]; //next_hop的mac地址
	bool type;  //标记能不能删除
	Route_entry* next;//用于连接

	Route_entry() {
		memset(this, 0, sizeof(*this));
	}
	void setNext(Route_entry* Next)
	{
		this->next = Next->next;
		this->next = Next;
	}
	void printEntry()
	{
		
		printf("[%d]   ", index );

		in_addr addr;
		addr.s_addr = des_ip;
		char* str = inet_ntoa(addr);
		addr.s_addr = des_ip;
		str = inet_ntoa(addr);
		printf("%*s", 18, str);

		addr.s_addr = netmask;
		printf("%*s", 18, str);

		addr.s_addr = next_hop;
		str = inet_ntoa(addr);
		printf("%*s", 18, str);

		printf("%*d\n", 5, type);
	}

};

class Route_table {
public:
	//循环链表
	Route_entry* head;
	Route_entry* tail;
	int num;

	Route_table() {
		head = new Route_entry;
		tail = new Route_entry;
	//	head->setNext(NULL);
		head->next = tail;
		tail->next = head;

			Route_entry* temp1 = new Route_entry;
			temp1->des_ip= (inet_addr(ip[0])) & (inet_addr(mask[0]));
			temp1->netmask = inet_addr(mask[0]);
			temp1->type = 0;//不可删类型
			Route_entry* temp2 = new Route_entry;
			temp2->des_ip = (inet_addr(ip[1])) & (inet_addr(mask[1]));
			temp2->netmask = inet_addr(mask[1]);
			temp2->type = 0;//不可删类型

			this->Insert(temp1);
			this->Insert(temp2);
	}

	//按netmask的降序排，符合最大匹配原则
	void Insert(Route_entry* r)
	{
		Route_entry* p = head->next;
		while (p != head)
		{
			//可能重复插入的情况，还未处理
			if (p == tail)
			{
				//证明此时为空的
				head->next = r;
				r->next = tail;
				num++;
				printf("Insert route entry Suscessfull!\n");
				break;
			}
			else if (p->next == tail || (p->netmask > r->netmask) && (r->netmask >= p->next->netmask))
			{
				r->next = p->next;
				p->next = r;
				num++;
				printf("Insert route entry Suscessfull!\n");
				break;
			}
			p = p->next;
		}
		//自动整理index,从1开始
		p = head->next;
		for (int i = 1; p != tail; i++) {
			p->index = i;
			p = p->next;
		}
	}

	void Delete(int index)  //根据索引删
	{
		Route_entry* p = head;
		if (index > num||index<=0)
		{
			printf("---------输入的序号无效！---------\n");
		}
		else
		{
			for (int i = 0; i < index-1; i++)
			{
				p = p->next;
			}
			//此时p指向想删的前一个
			if (p->next->type == 0&&p->index==index-1)
			{
				printf("---------默认路由不可删除！---------\n");
			}
			else if(p->index==index-1){
				Route_entry* q = p->next;
				p->next = q->next;
				delete q;
				num--;
				printf("++++++++No.[%d] Route entry delete successfully!++++++++\n", index);
				//自动更新索引
				p = head->next;
				for (int i = 1; p != tail; i++) {
					p->index = i;
					p = p->next;
				}
			}
			printf("找不到你想删的路由\n");
		}
	}

	DWORD  find(DWORD ip)
	{
		Route_entry* p = head->next;
		while (p != tail)
		{
			if ((p->netmask & ip) == p->des_ip)
			{
				if (p->next_hop)
					return p->next_hop;
				else
					return ip;

			}
			p = p->next;
		}
		return -1;
	}

	void PrintSelf() {
		Route_entry* p = head->next;
		printf("============================ Route Table ============================\n");
		printf("index");
		printf("%*s", 18, "Dst IP");
		printf("%*s", 19, "Net Mask");
		printf("%*s", 18, "Next Hop");
		printf("%*s \n", 5, "Type");
		while (p!=tail) {
			p->printEntry();
			p = p->next;
		}
		printf("======================================================================\n");

	}
};


#pragma pack() //恢复4字节对齐

typedef struct send_packet { //发送的数据包
	int len;
	BYTE pktData[2000];
	u_long targetIP;
	bool flag = 1; //是否有效，1为有效
	clock_t time;
} sndPkt_t;

//存缓存数据
// windows server2003不支持vector我真的会嘲笑！
//vector<send_packet>databuf;
send_packet databuf[50];
int sizeofbuf = 0;

/************************** ARP表项和表 ***********************************/
class Arp_entry {
public:
	DWORD ip;
	BYTE mac[6];
	int index;
	Arp_entry* next;
};

class Arp_table {
private:
	Arp_entry* head;
	Arp_entry* tail;
	int num;
public:
	Arp_table(){
		head = new Arp_entry;
		tail = new Arp_entry;
		head->next = tail;
		tail->next = head;
		num = 0;
	}
	void Insert(DWORD ip, BYTE mac[6])   //直接插在最前面
	{
		Arp_entry* r = new Arp_entry;
		r->ip = ip;
		memcpy(r->mac, mac, 6);
		if (head->next = tail)
		{
			head->next = r;
			r->next = tail;
			num++;
			printf("insert first arp entry ok\n");
			return;
		}
		else {
			r->next = head->next;
			head->next = r;
			num++;
			printf("insert arp entry ok\n");
			return;
		}
		//printf("insert arp entry fail\n");
	}

	//返回是否找到并且传回mac
	bool find(DWORD ip, BYTE mac[6])
	{
		memset(mac, 0, 6);
		Arp_entry* p = head->next;
		while (p != head)
		{
			if (ip == p->ip)
			{
				memcpy(mac, p->mac, 6);
				printf("Found mac ok!\n");
				
				return 1;
			}
			p = p->next;
		}
		in_addr addr;
		addr.s_addr = ip;
		char* str = inet_ntoa(addr);
		str = inet_ntoa(addr);
		//printf("%s",str);
	//	printf("Fail Found the mac of ip:%s \n",str);
		
		return 0;

	}

};
//提前实例化，传参有点麻烦
Arp_table arp_table;

/********************************* 对输出的定义 ************************************/
class Output {
public:
	Output();
	~Output();

	FILE* fp = nullptr;

	void output_arp(const char* a, ARPFrame_t);//arp类型
	void output_arp(const char* a, ARPFrame_t* pkt);
	void output_ip(const char* a, IPFrame_t*);//ip类型
	void output_icmp(const char* a);//icmp类型
}Log;
Output::Output() {
	this->fp = fopen("output.txt", "a+");
}
Output::~Output() {
	fclose(fp);
}
void Output::output_ip(const char* a, IPFrame_t* pkt) {
	fprintf(fp, a);
	fprintf(fp, "IP Packet-->");

	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* str = inet_ntoa(addr);
	fprintf(fp, "SrcIP： ");
	fprintf(fp, "%s  ", str);

	fprintf(fp, "DstIP： ");
	addr.s_addr = pkt->IPHeader.DstIP;
	str = inet_ntoa(addr);
	fprintf(fp, "%s  ", str);

	fprintf(fp, "SrcMAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);

	fprintf(fp, "DstMAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);

}
void Output::output_arp(const char* a, ARPFrame_t* pkt) {

	fprintf(fp, a);
	fprintf(fp, "ARP Packet-->");

	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* str = inet_ntoa(addr);
	fprintf(fp, "srcIP： ");
	fprintf(fp, "%s  ", str);

	fprintf(fp, "srcMAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);

	addr.s_addr = pkt->RecvIP;
	str = inet_ntoa(addr);
	fprintf(fp, "desIP： ");
	fprintf(fp, "%s  ", str);

}
void Output::output_arp(const char* a, ARPFrame_t pkt) {

	fprintf(fp, a);
	fprintf(fp, "ARP Packet-->");

	in_addr addr;
	addr.s_addr = pkt.SendIP;
	char* str = inet_ntoa(addr);
	fprintf(fp, "IP： ");
	fprintf(fp, "%s  ", str);

	fprintf(fp, "MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt.SendHa[i]);
	fprintf(fp, "%02X\n", pkt.SendHa[5]);

	addr.s_addr = pkt.RecvIP;
	str = inet_ntoa(addr);
	fprintf(fp, "desIP： ");
	fprintf(fp, "%s  ", str);

}
void Output::output_icmp(const char* a) {

	fprintf(fp, a);
}

/****************************打开网卡，获取IP地址**********************************/
void getnetwork()
{

	int i = 0;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&Header, errbuf) == -1)
	{
		printf("获取设备失败%s\n", stderr, errbuf);

	}
	for (currentDevice = Header; currentDevice!=NULL; currentDevice = currentDevice->next)
	{
		printf("%d.%s\n", ++i, currentDevice->name);
		if (currentDevice->description)
			printf("(%s)\n", currentDevice->description);
		else
			printf("no description available\n");
		if (i == 0)
		{
			printf("Error:没有找到端口,请检查。\n");
			//return -1;
		}
		for (a = currentDevice->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				printf("\n==========================================================\n");
				char str[INET_ADDRSTRLEN];
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("IP Address：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				printf("Net Mask：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr));
				printf("Broadcast Address：%s\n", str);

			}
		}
	}

	currentDevice = Header;
	int tool;
	printf("=============Enter the interface number:============= \n");
	scanf("%d", &tool);
	if (tool<1 || tool>i)
	{
		//cout << "Interface number out of range!" << endl << "端口号不在正确范围内！" << endl;
		//pcap_freeHeader(Header);
		//return -1;
		printf("端口号不在正确范围内！\n");
	}
	/* 跳转到选中的适配器 */
	for (i = 0; i < tool - 1; i++) {
		currentDevice = currentDevice->next;
	}
	int num = 0;
	printf("=====本机 IP 地址如下=====\n");
	for (a = currentDevice->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			//inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), ip, sizeof(ip));
			strcpy(ip[num], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			strcpy(mask[num], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			printf("%s\t", ip[i]);
			printf("%s\n", mask[i]);
			num++;

		}
	}
	if((targetDevice = pcap_open(currentDevice->name, 
		100,
		PCAP_OPENFLAG_PROMISCUOUS, 
		1000, 
		NULL,
		errbuf))==NULL)
	{
		printf("Unable to open the adapter %s \n", errbuf);
	}
	pcap_freealldevs(Header);
}

/*****************************获取本地MAC地址**********************************/
void GetLocalMac()
{
	char* tool = ip[0];
	DWORD ip = inet_addr(tool);
	memset(Local_Mac, 0, sizeof(Local_Mac));
	ARPFrame_t ARPFrame1;
	for (int i = 0; i < 6; i++) {
		ARPFrame1.FrameHeader.DesMAC[i] = 0xff;
		ARPFrame1.FrameHeader.SrcMAC[i] = 0x0f;
		ARPFrame1.SendHa[i] = 0x0f;
		ARPFrame1.RecvHa[i] = 0x00;
	}
	ARPFrame1.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame1.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame1.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame1.HLen = 6;//硬件地址长度为6
	ARPFrame1.PLen = 4;//协议地址长为4
	ARPFrame1.Operation = htons(0x0001);//操作为ARP请求
	ARPFrame1.SendIP = inet_addr("10.10.10.10");
	ARPFrame1.RecvIP = ip;

	struct pcap_pkthdr* adhandleheader;
	const u_char* adhandledata;
	//struct pcap_pkthdr* header = new pcap_pkthdr;


	while (1)
	{
		if (pcap_sendpacket(targetDevice, (u_char*)&ARPFrame1, sizeof(ARPFrame_t)) != 0)
		{
			printf("为了获取本地mac而发送的ARP数据包发送失败！\n");
			continue;
		}
		else
		{
			printf("为了获取本地mac而发送的ARP数据包发送成功！\n");
			break;
		}
	}
	int catch_t = 0;
	while (1)
	{
			//捕获返回的ARP数据包
			 catch_t = pcap_next_ex(targetDevice, &adhandleheader, &adhandledata);
			 if (catch_t > 0)
			{
				 //htons 将短整数从主机字节序转换为网络字节序的函数
				 if (*(unsigned short*)(adhandledata + 12) == htons(0x0806)  //ARP类型
					 && *(unsigned short*)(adhandledata + 20) == htons(0x0002)  // 检查 ARP 数据包中的操作码是否为应答 (0x0002)。
					 && *(unsigned long*)(adhandledata + 28) == ARPFrame1.RecvIP)   //目标 IP 地址字段在 ARP 数据包中位于偏移量 28
				 {
					 for (int i = 0; i < 6; i++) {
						 Local_Mac[i] = *(unsigned char*)(adhandledata + 22 + i);
					 }
					 printf("\n=====成功获取Local的mac=====\n");
					 printf("MAC:");
					 for (int i = 0; i < 6; i++) {
						 if (i == 5)
							 printf("%2X\n", Local_Mac[i]);
						 else
							 printf("%2X-", Local_Mac[i]);
					 }
					 break;
				 }

			}
		}

	
}

/*****************辅助函数************************/
bool is_mac_same(BYTE mac1[6], BYTE mac2[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (mac1[i] != mac2[i])
			return false;
	}
	return true;
}
// 计算校验和
unsigned short cal_checksum(unsigned short* buffer, int size)
{
	unsigned long check = 0;
	while (size > 1)
	{
		check += *buffer++;
		// 16位相加
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		// 最后可能有单独8位
		check += *(unsigned char*)buffer;
	}
	// 将高16位进位加至低16位
	check = (check >> 16) + (check & 0xffff);
	check += (check >> 16);
	// 取反
	return (unsigned short)(~check);
}

// 判断IP数据包头部校验和是否正确
int test_checksum(char* buffer)
{
	// 获得IP头内容
	IPHeader_t* ip_header = (IPHeader_t*)buffer;
	// 备份原来的校验和
	unsigned short checksumBuf = ip_header->Checksum;
	unsigned short check_buff[sizeof(IPHeader_t)];
	// 设IP头中的校验和为0
	ip_header->Checksum = 0;

	memset(check_buff, 0, sizeof(IPHeader_t));
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	// 计算IP头部校验和
	ip_header->Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));

	// 与备份的校验和进行比较
	if (ip_header->Checksum == checksumBuf)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


//填充ICMP报文
void icmp_Packet(BYTE type,BYTE code,const u_char*data) {
	u_char* Buffer = new u_char[70];

	// 填充帧首部
	memcpy(((FrameHeader_t*)Buffer)->DesMAC, ((FrameHeader_t*)data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)Buffer)->SrcMAC, ((FrameHeader_t*)data)->DesMAC, 6);
	((FrameHeader_t*)Buffer)->FrameType = htons(0x0800);

	// 填充IP首部
	((IPHeader_t*)(Buffer + 14))->Ver_HLen = ((IPHeader_t*)(data + 14))->Ver_HLen;
	((IPHeader_t*)(Buffer + 14))->TOS = ((IPHeader_t*)(data + 14))->TOS;
	((IPHeader_t*)(Buffer + 14))->TotalLen = htons(56);
	((IPHeader_t*)(Buffer + 14))->ID = ((IPHeader_t*)(data + 14))->ID;
	((IPHeader_t*)(Buffer + 14))->Flag_Segment = ((IPHeader_t*)(data + 14))->Flag_Segment;
	((IPHeader_t*)(Buffer + 14))->TTL = 64;
	((IPHeader_t*)(Buffer + 14))->Protocol = 1;
	((IPHeader_t*)(Buffer + 14))->SrcIP = ((IPHeader_t*)(data + 14))->DstIP;
	((IPHeader_t*)(Buffer + 14))->DstIP = ((IPHeader_t*)(data + 14))->SrcIP;
	((IPHeader_t*)(Buffer + 14))->Checksum = htons(cal_checksum((unsigned short*)(Buffer + 14), 20));

	// 填充ICMP首部
	((ICMPHeader_t*)(Buffer + 34))->Type = type;
	((ICMPHeader_t*)(Buffer + 34))->Code = code;
	((ICMPHeader_t*)(Buffer + 34))->Id = 0;
	((ICMPHeader_t*)(Buffer + 34))->Seq = 0;
	((ICMPHeader_t*)(Buffer + 34))->Checksum = htons(cal_checksum((unsigned short*)(Buffer + 34), 8));

	//复制 IP 头部及其后续的数据
	memcpy((u_char*)(Buffer + 42), (IPHeader_t*)(data + 14), 20);
	//源数据包中的 ICMP 数据部分
	memcpy((u_char*)(Buffer + 62), (u_char*)(data + 34), 8);
	pcap_sendpacket(targetDevice, (u_char*)Buffer, 70);

	if (type == 11)
	{
		Log.output_icmp("【send ：ICMP TIMEOUT packet】-->\n");
	}
	if (type == 3)
	{
		Log.output_icmp("【send ：ICMP UNREACHABLE packet】-->\n");
	}

}

//获取ip对应的mac
void get_mac(DWORD ip_t)
{
	ARPFrame_t ARPFrame;
	//将DesMAC设置为广播地址
	//SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
		ARPFrame.FrameHeader.SrcMAC[i] = Local_Mac[i];
		ARPFrame.SendHa[i] = Local_Mac[i];
	}
	
	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	//将ARPFrame->SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);
	//将ARPFrame->RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	ARPFrame.RecvIP = ip_t;

	pcap_sendpacket(targetDevice, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	Log.output_arp("【SEND for get mac】", ARPFrame);
}




/********************接收线程****************************/
DWORD WINAPI recv_thread(LPVOID lparam)
{
	Route_table route_table = *(Route_table*)(LPVOID)lparam;
	struct bpf_program fcode;
	//过滤
	char packet_filter[] = "ip or arp";
	if (pcap_compile(targetDevice, &fcode, packet_filter, 1, bpf_u_int32(mask[0])) < 0)
	{
		fprintf(stderr, "\nError compiling filter: wrong syntax.\n");
		system("pause");
		return -1;
	}
	//绑定过滤器
	if (pcap_setfilter(targetDevice, &fcode) < 0)
	{
		fprintf(stderr, "Error：应用过滤器时发生错误！\n");
		pcap_freealldevs(Header);
		system("pause");
		return -1;
	}
	//进入接收循环
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;  //存收到的数据
	while (1)
	{
		if (pcap_next_ex(targetDevice, &pkt_header, &pkt_data) == 0)
		{
			continue;
		}
		FrameHeader_t* Header = (FrameHeader_t*)pkt_data;
		//只收mac和本地相同的帧
		if (is_mac_same(Header->DesMAC, Local_Mac))
		{
			//ARP帧
			if (ntohs(Header->FrameType) == 0x806)
			{
				ARPFrame_t* ARPdata = (ARPFrame_t*)pkt_data;
				//收到响应包，存mac
				//LOG
				Log.output_arp("【ARP RECV】", ARPdata);
				if (ARPdata->Operation == ntohs(0x0002))
				{
					BYTE temp[6];
					if (!arp_table.find(ARPdata->SendIP, temp)) {
				
						arp_table.Insert(ARPdata->SendIP, ARPdata->SendHa);
					}

					for (int i = 0; i < sizeofbuf; i++)
					{
						send_packet tool = databuf[i];
						if (!tool.flag)
							continue;
						if (clock() - tool.time >= TIMELIMIT)
						{
							tool.flag = 0;  //意思是超时不再重发
							continue;
						}
						if (tool.targetIP == ARPdata->SendIP)
						{
							IPFrame_t* IPdata = (IPFrame_t*)tool.pktData;
							for (int i = 0; i < 6; i++) {
								IPdata->FrameHeader.DesMAC[i] = ARPdata->SendHa[i];
								IPdata->FrameHeader.SrcMAC[i] = Local_Mac[i];
							}
							//发数据
							pcap_sendpacket(targetDevice, (u_char*)tool.pktData, tool.len);
							databuf[i].flag = 0;
							//清缓存
							//databuf.erase(databuf.begin() + i);
							//LOG
							Log.output_ip("【Send IP(buffer)】", (IPFrame_t*)tool.pktData);
						}
					}
				}
			}
			//IP帧
			else if (ntohs(Header->FrameType) == 0x800)
			{
				IPFrame_t* data = (IPFrame_t*)pkt_data;
				//LOG
				DWORD dst_ip = data->IPHeader.DstIP;
				DWORD next_hop = route_table.find(dst_ip);
				if (data->IPHeader.TTL <= 0)
				{
					icmp_Packet(11, 0, pkt_data);
					Log.output_ip("【Recv IP(timeout)-can't transmit】", data);
					continue;
				}
				IPHeader_t* IpHeader = &(data->IPHeader);
				if (test_checksum((char*)IpHeader) == 0)
				{
					printf("checksum差错\n");
					continue;
				}
				if (next_hop == -1) {  //没在route table中找到路径
					//ICMPPacket
					icmp_Packet(3, 0, pkt_data);
					Log.output_ip("【Recv IP(dont'have path))-can't transmit】", data);
						continue;
				}
				else
				{
					//进行转发数据机制
					send_packet send;
					send.targetIP = next_hop;
					for (int i = 0; i < 6; i++)
					{
						data->FrameHeader.SrcMAC[i] = Local_Mac[i];
					}
					data->IPHeader.TTL -= 1;
					//差错检验
					unsigned short check_buff[sizeof(IPHeader_t)];
					

					memset(check_buff, 0, sizeof(IPHeader_t));
					IPHeader_t* ip_header = &(data->IPHeader);
					memcpy(check_buff, ip_header, sizeof(IPHeader_t));

					// 校验和
					data->IPHeader.Checksum = 0;
					data->IPHeader.Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));


					//如果有mac
					if (arp_table.find(next_hop, data->FrameHeader.DesMAC))
					{
						memcpy(send.pktData, pkt_data, pkt_header->len);
						send.len = pkt_header->len;
						if (!pcap_sendpacket(targetDevice, (u_char*)send.pktData, send.len))
						{
							//发送错误了
							continue;
							//是否存进buffer 呢
						}
						//LOG
						Log.output_ip("【Transmit IP】", (IPFrame_t*)send.pktData);
					}
					else {
						if (sizeofbuf < 50)
						{
							send.len = pkt_header->len;
							memcpy(send.pktData, pkt_data, pkt_header->len);
							databuf[sizeofbuf++] = send;
							Log.output_ip("【Save IP in buffer】", data);
							send.time = clock();
							send.flag = 1;
						//发请求mac
							get_mac(send.targetIP);
						}
						else
						{
							//log
							//溢出
							Log.output_ip("【IP dumped(buffer overload)】", data);
						}
						
					}
				}



			}
		}

	}
}


