#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "nids.h"	/*libnids Header Type*/

char ascii_string[10000];
char* char_to_ascii(char ch)	//Show the details of Proc
{
	char* string;
	ascii_string[0] = 0; 
	string = ascii_string;
	if (isgraph(ch))	//Printable
	{
		*string++ = ch;
	}
	else if(ch == ' ')	//SPACE
	{
		*string++ = ch;
	}
	else if (ch == '\n' || ch == '\r') //ENTER and TAB
	{
		*string++ = ch;
	}
	else	//Others replaced by '.'
	{
		*string++ = '.';
	}
	*string = 0;
	return ascii_string;
}

//Down here are callback func, used to analysis the connection and status of TCP, and the transport data
void tcp_portocol_callback(struct tcp_stream* tcp_connection, void** arg)
{
	int i;
	char address_string[1024];
	char content[65535];
	char content_urgent[65535];
	struct tuple4 ip_and_port = tcp_connection->addr;	//Get the addr and port of TCP conn
	strcpy(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));	//Get src addr
	sprintf(address_string + strlen(address_string), ": %i", ip_and_port.source);	//Get src port
	strcat(address_string, "<--->");
	strcat(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));	//Get dst addr
	sprintf(address_string + strlen(address_string), ": %i", ip_and_port.dest);	//Get dst port
	strcat(address_string, "\n");
	switch (tcp_connection->nids_state)				//Judge status of LIBNIDS
	{
		case NIDS_JUST_EST:							//Conn between Client and Server has established
			tcp_connection->client.collect++;		//Client recv data
			tcp_connection->server.collect++;		//Svr recv data
			tcp_connection->server.collect_urg++;	//Svr recv urgent data
			tcp_connection->client.collect_urg++;	//Client recv urgent data
			printf("%sTCP connection has established\n", address_string);
			return;
		case NIDS_CLOSE:							//Conn close normaly
			printf("----------------------------------------------\n");
			printf("%sTCP connection close normaly\n", address_string);
			return;
		case NIDS_RESET:							//Conn closed by RST
			printf("----------------------------------------------\n");
			printf("%sTCP connection closed by RST\n", address_string);
			return;
		case NIDS_DATA:								//New msg transport
		{
			struct half_stream* hlf;				//One side's msg, could be clt and svr
			if (tcp_connection->server.count_new_urg)
			{										//TCP svr recv new urgent data
				printf("------------------------------------------\n");
				strcpy(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.source);
				strcat(address_string, " urgent---> ");
				strcat(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.dest);
				strcat(address_string, "\n");
				address_string[strlen(address_string) + 1] = 0;
				address_string[strlen(address_string)] = tcp_connection->server.urgdata;
				printf("%s\n", address_string);
				return;
			}
			if (tcp_connection->client.count_new_urg)
			{										//TCP clt recv new urgent data
				printf("------------------------------------------\n");
				strcpy(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.source);
				strcat(address_string, " <---urgent ");
				strcat(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.dest);
				strcat(address_string, "\n");
				address_string[strlen(address_string) + 1] = 0;
				address_string[strlen(address_string)] = tcp_connection->client.urgdata;
				printf("%s\n", address_string);
				return;
			}
			if (tcp_connection->client.count_new)
			{										//Clt recv new data
				hlf = &tcp_connection->client;		//hlf means clt's TCP conn info
				strcpy(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.source);
				strcat(address_string, " <--- ");
				strcat(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.dest);
				strcat(address_string, "\n");
				printf("------------------------------------------\n");
				printf("%s\n", address_string);
				memcpy(content, hlf->data, hlf->count_new);
				content[hlf->count_new] = '\0';
				printf("Client receive data\n");
				for (i = 0; i < hlf->count_new; i++)
				{
					printf("%s\n", char_to_ascii(content[i]));
													//Output the data recv by clt in printable charactor
				}
				printf("\n");
			}
			else
			{										//Svr recv new data
				hlf = &tcp_connection->server;		//Svr's TCP conn info
				strcpy(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.source);
				strcat(address_string, " ---> ");
				strcat(address_string, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
				sprintf(address_string + strlen(address_string), ": %i", ip_and_port.dest);
				strcat(address_string, "\n");
				printf("------------------------------------------\n");
				printf("%s\n", address_string);
				memcpy(content, hlf->data, hlf->count_new);
				content[hlf->count_new] = '\0';
				printf("Server receive data\n");
				for (i = 0; i < hlf->count_new; i++)
				{
					printf("%s\n", char_to_ascii(content[i]));
													//Outpur the data recv by svr in printable charactor
				}
				printf("\n");
			}
		}
	default:
		break;
	}
	return;
}
void main()
{
	if (!nids_init())	/*Libnids init*/
	{
		printf("ERROR: %s\n", nids_errbuf);
		exit(1);
	}
	nids_register_tcp(tcp_portocol_callback);			//Reg callback function
	nids_run();											//loop to capture datapacket
}

