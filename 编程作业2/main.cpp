#include <iostream>
#include <pcap.h>
#include <Winsock2.h>
#include <cstdio>
#include <cstring>
#include <iomanip>
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#pragma warning(disable:6011)
using namespace std;
//表示按照一个字节对齐，也就是每个成员都放在一个字节的边界上，不管成员的大小是多少。
#pragma pack(1)
typedef struct FrameHeader_t//帧首部
{
    BYTE DesMAC[6];  //目的地址
    BYTE SrcMAC[6];  //源地址
    WORD FrameType;  //帧类型
}FrameHeader_t;
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

#pragma pack() // 恢复默认对齐方式
void output_MAC(BYTE MAC_addr[6])
{
    for (int i = 0; i <= 5; i++)
    {
        cout << setw(2) << setfill('0') << hex << (int)MAC_addr[i];
        if (i != 5)cout << "-";
    }
}
void output_IP(DWORD IP_addr)
{
    BYTE* p = (BYTE*)&IP_addr;
    for (int i = 0; i <= 3; i++, p++)
    {
        cout << dec << (int)*p;
        if (i != 3)cout << ".";
    }
}
void output_ARP(ARPFrame_t* IPPacket)//输出ARP帧
{
    cout << "ARP数据包如下：" << endl;
    //cout << "目的MAC地址：" << endl;
    //output_MAC(IPPacket->FrameHeader.DesMAC);
    //cout << "源MAC地址：" << endl;
    //output_MAC(IPPacket->FrameHeader.SrcMAC);
    cout << "帧类型: " << hex << ntohs(IPPacket->FrameHeader.FrameType) << endl;
    cout << "硬件类型: " << hex << ntohs(IPPacket->HardwareType) << endl;
    cout << "协议类型: " << hex << ntohs(IPPacket->ProtocolType) << endl;
    cout << "硬件地址长度: " << hex << (int)IPPacket->HLen << endl;
    cout << "协议地址长度: " << hex << (int)IPPacket->PLen << endl;
    cout << "报文类型: " << hex << ntohs(IPPacket->Operation) << endl;
    cout << "发送端 MAC 地址: ";
    output_MAC(IPPacket->SendHa);
    cout << endl;
    cout << "发送端 IP 地址: ";
    output_IP(IPPacket->SendIP);
    cout << endl;
    cout << "目的端 MAC 地址: ";
    output_MAC(IPPacket->RecvHa);
    cout << endl;
    cout << "目的端 IP 地址: ";
    output_IP(IPPacket->RecvIP);
    cout << endl;

}

void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;

    // 获取所有可用的网络设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }
    pcap_addr_t* a;
    // Print the list
    for (d = alldevs; d; d = d->next) {
        std::cout << ++i << ": " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        std::cout << std::endl;
        a = d->addresses;
        while (a != NULL) 
        {
            if (a->addr->sa_family == AF_INET)
            {
                cout << "  IP地址: " << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
            }
            a = a->next;
        }
    }

    if (i == 0) {
        std::cerr << "No interfaces found!" << std::endl;
        return 1;
    }

    std::cout << "Enter the interface number (1-" << i << "): ";
    int inum;
    std::cin >> inum;

    if (inum < 1 || inum > i) {
        std::cerr << "Invalid interface number!" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Jump to the selected adapter
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // Open the capture interface
    pcap_t* adhandle;
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        std::cerr << "Unable to open the adapter: " << d->name << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "Listening on: " << d->description << std::endl;

    //过滤器
    u_int netmask;
    //掩码，捕获特定本地网络
    netmask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    struct bpf_program fcode;
    //表示过滤以太网帧（ether）中协议类型字段为 ARP 的数据包。
    char packet_filter[] = "ether proto \\arp";
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        cout << "Error：编译过滤器时发生错误！" << endl;
        pcap_freealldevs(alldevs);
        throw - 5;
    }
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        cout << "Error：应用过滤器时发生错误！" << endl;
        pcap_freealldevs(alldevs);
        throw - 6;
    }
    ARPFrame_t ARPFrame;
    ARPFrame_t* IPPacket = 0;
    DWORD SIP, ReIP, MIP;
    for (i = 0; i < 6; i++)
    {
        ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//表示广播
        ARPFrame.FrameHeader.SrcMAC[i] = 0x00;//设置为任意 MAC 地址
    }
    ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
    ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
    ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
    ARPFrame.HLen = 6;//硬件地址长度为6
    ARPFrame.PLen = 4;//协议地址长为4
    ARPFrame.Operation = htons(0x0001);//操作为ARP请求
    for (int i = 0; i < 5; i++)
    {
        ARPFrame.SendHa[i] = 0x11;//设置为任意 MAC 地址
        ARPFrame.RecvHa[i] = 0;//置0
    }
    //SendIP
    SIP = ARPFrame.SendIP = htonl(0x00000000);//设置为任意 IP 地址
    //RecvIP，之前选的
    //pcap_addr_t* a;
    for (a = d->addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            ReIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
        }
    }
    struct pcap_pkthdr* adhandleheader;
    const u_char* adhandledata;
    //发送ARP报文
    if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        cout << "ARP数据包发送失败！" << endl;
        pcap_freealldevs(alldevs);
        throw - 7;
    }
    else
    {
        cout << "ARP数据包发送成功！" << endl;
    }
    int catch_count = 0;
    while (catch_count <= 10)
    {
        //捕获返回的ARP数据包
        int catch_t = pcap_next_ex(adhandle, &adhandleheader, &adhandledata);
        if (catch_t == -1)
        {
            cout << "捕获返回ARP失败" << endl;
            pcap_freealldevs(alldevs);
            throw - 8;
            break;
        }
        else if (catch_t == 0)
        {
            cout << "暂未获得数据，正在重新尝试" << endl;
            cout << "第 " << ++catch_count << " 次尝试" << endl;
        }
        else if (catch_t > 0)
        {
           cout << "捕获到数据！这是第" << catch_count << "次尝试！" << endl;
            IPPacket = (ARPFrame_t*)adhandledata;
            if (SIP == IPPacket->RecvIP && ReIP == IPPacket->SendIP)
            {
                cout << "成功获取回复的数据报！" << endl;
                output_ARP(IPPacket);
                cout << endl;
                cout << "所以本机IP地址与MAC地址的对应关系如下：" << endl;
                cout << "IP：";
                output_IP(IPPacket->SendIP);
                cout << endl;
                cout << "MAC: ";
                output_MAC(IPPacket->SendHa);
                cout << endl;
                break;
            }

        }
    }


    cout << "向网络发送数据包" << endl;
    char pip[16];
    cout << "请输入目的IP地址" << endl;
    cin >> pip;
    ReIP = ARPFrame.RecvIP = inet_addr(pip);
    SIP = ARPFrame.SendIP = IPPacket->SendIP;
    for (i = 0; i < 6; i++)
    {
        //将本机IP填入报文
        ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
    }
    if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        cout << "ARP数据包发送失败！" << endl;
        pcap_freealldevs(alldevs);
        throw - 10;
    }
    else
    {
        cout << "ARP数据包发送成功！" << endl;
    }

    catch_count = 0;
    while (catch_count <= 10)
    {
        //捕获返回的ARP数据包
        int catch_t = pcap_next_ex(adhandle, &adhandleheader, &adhandledata);
        if (catch_t == -1)
        {
            cout << "捕获返回ARP失败" << endl;
            pcap_freealldevs(alldevs);
            throw - 8;
            break;
        }
        else if (catch_t == 0)
        {
            cout << "暂未获得数据，正在重新尝试" << endl;
            cout << "第 " << ++catch_count << " 次尝试" << endl;
        }
        else if (catch_t > 0)
        {
           // cout << "捕获到数据！这是第" << catch_count << "次尝试！" << endl;
            IPPacket = (ARPFrame_t*)adhandledata;
            if (SIP == IPPacket->RecvIP && ReIP == IPPacket->SendIP)
            {
                cout << "成功获取回复的数据报！" << endl;
                output_ARP(IPPacket);
                cout << endl;
                cout << "所以本机IP地址与MAC地址的对应关系如下：" << endl;
                cout << "IP：";
                output_IP(IPPacket->SendIP);
                cout << endl;
                cout << "MAC: ";
                output_MAC(IPPacket->SendHa);
                cout << endl;
                break;
            }

        }
    }



    // Set a packet handler callback
    pcap_loop(adhandle, 0, packet_handler, NULL);

    // Close the handle
    pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    return 0;

}

void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

}
