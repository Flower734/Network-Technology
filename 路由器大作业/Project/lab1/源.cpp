#include"Router.h"
using namespace std;


int main()
{
	//���Ȼ�ȡ��������ȡIP��ַ�������
	getnetwork();
	//��ȡ���ص�mac�����
	GetLocalMac();


	Route_table route_table;
	

	//�����߳�
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
			printf("Destination Net��");
			scanf("%s", &n);
			insert->des_ip = inet_addr(n);

			printf("Net Mask��");
			scanf("%s", &m);
			insert->netmask = inet_addr(m);

			printf("Next Hop��");
			scanf("%s", &h);
			insert->next_hop = inet_addr(h);

			insert->type = 1;//���Ϊ����ɾ
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