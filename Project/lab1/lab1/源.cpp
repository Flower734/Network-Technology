#include"Router.h"
using namespace std;


int main()
{
	//首先获取网卡，获取IP地址，并输出
	getnetwork();
	//获取本地的mac并输出
	GetLocalMac();


	Route_table route_table;
	

	//创建线程
	hThread = CreateThread(NULL, NULL, recv_thread, LPVOID(&route_table), 0, &dwThreadId);
	int choice;
	while (1)
	{
		printf("\n\n ======================== Choose ===========================\n");
		printf("[1] INSERT Route entry\n");
		printf("[2] Delete Route entry\n");
		printf("[3] PRINT  Route table\n");
		scanf("%d", &choice);
		
		switch (choice) {
		case 1:
		{
			Route_entry* insert = new Route_entry;
			char m[50], n[50], h[50];
			printf("Please Enter: \n");
			printf("Destination Net：");
			scanf("%s", &n);
			insert->des_ip = inet_addr(n);

			printf("Net Mask：");
			scanf("%s", &m);
			insert->netmask = inet_addr(m);

			printf("Next Hop：");
			scanf("%s", &h);
			insert->next_hop = inet_addr(h);

			insert->type = 1;//标记为可以删
			route_table.Insert(insert);
			break;
		}
			
		case 2:
		{
			printf("Please Enter the index of the route entry u want to delete:  \n");
			route_table.PrintSelf();
			int i;
			scanf("%d", &i);
			route_table.Delete(i);
			break;
		}
		case 3:
		{
			route_table.PrintSelf();
			break;
		}
		default:
		{
			printf("please input corrert choic!\n");
			break;
		}
		}
	}
	//int i;
	//scanf("%d", &i);
	return 0;

}