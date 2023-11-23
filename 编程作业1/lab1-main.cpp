#include <Winsock2.h>
#include "pcap.h"
#include <iostream>
#include <iomanip>
#include <cstdio>

//将 Windows 套接字库（ws2_32.lib）链接到生成的可执行文件中。
#pragma comment(lib,"ws2_32.lib")

//禁止特定的编译器警告
#pragma warning(disable:4996)
#pragma warning(disable:6011)
using namespace std;

#define HAVE_REMOTE

//存储MAC地址
struct MAC
{
    uint8_t source[6];//源MAC地址
	uint8_t destination[6];//目的MAC地址
	
    //表示以太网帧的类型。这个字段通常标识了以太网帧中携带的协议类型，如IPv4、IPv6、ARP等。
	uint16_t ether_type;
};
//存储IP地址和校验和的结构体
struct IP
{
	uint8_t IP_length : 4,
		ip_version : 4;

	uint8_t ip_tos;
	uint16_t ip_length;
	uint16_t ip_checksum;//校验和字段
	struct in_addr  ip_source_address;//源地址
	struct in_addr  ip_destination_address;//目的地址
};
/* packet handler 函数 */
/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	struct MAC* ethernet_protocol; /*以太网协议变量*/
	struct IP* ip_protocol;/*ip协议变量*/
	ip_protocol = (struct IP*)(pkt_data + 14); /*处理ip数据包的内容*/
	char timestr[16];
	time_t local_tv_sec;
	u_char* macsave;
	cout << "捕获到数据包!" << endl;
	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	cout << "捕获时间:    ";
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	cout << timestr << endl;
	cout << "数据包长度:  " << header->len << "字节" << endl;
	ethernet_protocol = (struct MAC*)pkt_data;
	/*源MAC地址*/
	macsave = ethernet_protocol->source;
	cout << "源MAC地址:   ";
	printf("%02x:%02x:%02x:%02x:%02x:%02x", *macsave, *(macsave + 1), *(macsave + 2), *(macsave + 3), *(macsave + 4), *(macsave + 5));//经过测试，cout会产生奇怪的bug，故用也能支持的printf来表示
	/*目的MAC地址*/
	cout << endl;
	macsave = ethernet_protocol->destination;
	cout << "目的MAC地址: ";
	printf("%02x:%02x:%02x:%02x:%02x:%02x", *macsave, *(macsave + 1), *(macsave + 2), *(macsave + 3), *(macsave + 4), *(macsave + 5));
	cout << endl;
	/*源ip地址*/
	cout << "源IP地址:    " << inet_ntoa(ip_protocol->ip_source_address) << endl;
	/*目的ip地址*/
	cout << "目的IP地址:  " << inet_ntoa(ip_protocol->ip_destination_address) << endl;
	//cout << "帧类型：" << "以太网帧" << endl;
	/*校验和字段*/
	cout << "校验和字段:  " << ip_protocol->ip_checksum << endl;
	cout << endl << endl;
}
int main()
{
    //pcap_if_t表示网络接口信息的结构体
    //name,description,next,addresses
	pcap_if_t* Header;
	pcap_addr_t* a;
	pcap_t* adhandle;
	int inum;
	char err[PCAP_ERRBUF_SIZE];
	cout << "开始扫描"<<endl;
	//扫描所有端口并展示
    //pcap_findHeader_ex获取可用的网络接口列表，并将其存储在 Header 链表中
    //返回-1表示失败
    //PCAP_SRC_IF_STRING 是一个字符串，通常用于指定捕获数据包的来源，它告诉函数从网络接口捕获数据包。
    //NULL表示过滤条件
	if (pcap_findHeader_ex(PCAP_SRC_IF_STRING,NULL,&Header,err) == -1)
	{
		cout << "获取端口失败"<<endl;
		return -1;
	}
    //Header存储一个链表的头部
    //每个节点代表一个可用的网络接口。该链表包含了有关每个接口的信息，如名称、描述等。
    //输出所有网络接口的信息
    int i=0;
    pcap_if_t* tool=Header;
	for (tool; tool != NULL; d = d->next)
	{
		cout << ++i << ": " << tool->name << endl;
        cout << tool->description << endl;
		
	}
    //如果没找到端口
	if (i == 0)
	{
		cout << "Error:没有找到端口,请检查。"<<endl;
		return -1;
	}

    //开始获取数据包
	cout << "Enter the interface number:(range:1-" << i << ")" << endl << "请输入进入的端口号:（范围：1-" << i << "）" << endl;
	cin >> inum;
	if (inum<1 || inum>i)
	{
		cout << "Interface number out of range!" << endl << "端口号不在正确范围内！" << endl;
		pcap_freeHeader(Header);
		return -1;
	}
	/* 跳转到选中的适配器 */
	for (d = Header, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,
		65535,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		err
	)) == NULL)
	{
		cout << stderr << endl << "Unable to open the adapter, it is not supported by NPcap" << endl << "无法打开，请检查是否受到 NPcap 支持！" << d->name;
		pcap_freeHeader(Header);
		return -1;
	}
	cout << "listening on : " << d->description << endl;
	pcap_freeHeader(Header);
	int pnum = 0;
	cout << "Enter the number of data package needed!" << endl << "输入捕获数据包数量" << endl;
	cin >> pnum;
	//main中通过调用pcap_loop来捕获pnum个数据包
	pcap_loop(adhandle, pnum, packet_handler, NULL);
	cout << "Packages caputuring finished!" << endl << "数据报捕获结束！" << endl;
	system("pause");
	return 0;
}
