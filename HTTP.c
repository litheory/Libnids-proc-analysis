#include "nids.h"
char ascii_string[10000];
char* char_to_ascii(char ch)
{
	char* string;
	ascii_string[0] = 0;
	string = ascii_string;
	if (isgraph(ch))
	{
		*string++ = ch;
	}
	else if (ch == ' ')
	{
		*string++ = ch;
	}
	else if (ch == '\n' || ch == '\r')
	{
		*string++ =ch;
	}
	else
	{
		*string++ = '.';
	}
	*string = 0;
	return ascii_string;
}
//The following function is an analysis of the data received by the browser
void parse_client_data(char content[], int number)
{
	char temp[1024];
	char str1[1024];
	char str2[1024];
	char str3[1024];
	int i;
	int k;
	int j;
	char entity_content[1024];
	if (content[0] != 'H' && content[1] != 'T' && content[2] != 'T' && content[3] != 'P')
	{
		printf("Entity Content(Continued): \n");
		for (i = 0; i < number; i++)
		{
			printf("%s", char_to_ascii(content[i]));
		}
		printf("\n");
	}
	else
	{
		for (i = 0; i < strlen(content); i++)	
		{
			k++;
			continue;
		}
		for (j = 0; j < k; j++)
			temp[j] = content[j + 1 - k];
		temp[j] = '\0';
		if (strstr(temp, "HTTP"))
		{
			printf("Status Behavior: ");
			printf("%s\n", temp);
			sscanf(temp, "%s %s %s", str1, str2);
			printf("HTTP protocol:%s\n", str1);
			printf("Status Code:%s\n", str2);
		}
		if (strstr(temp, "Date"))
		{
			printf("Date:%s\n", temp +strlen("Date:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Server"))
		{
			printf("Server:%s\n", temp + strlen("Server:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Cache-Control"))
		{
			printf("Cache-Control:%s\n", temp + strlen("Cache-Control:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Expires"))
		{
			printf("Expires:%s\n", temp + strlen("Expires:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Last-Modified"))
		{
			printf("Last-Modified:%s\n", temp + strlen("Last-Modified:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "ETag"))
		{
			printf("Etag:%s\n", temp + strlen("ETag"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Accept-Ranges"))
		{
			printf("Accept-Ranges:%s\n", temp + strlen("Accept-Ranges"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Content-Length"))
		{
			printf("Content-Length:%s\n", temp + strlen("Content-Length"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Connection"))
		{
			printf("Connection:%s\n", temp + strlen("Connection:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Content-Type"))
		{
			printf("Content-Type:%s\n", temp + strlen("Content-Type"));
			printf("%s\n", temp);
		}
		//Get Entity Content
		if ((content[i] == '\n') && (content[i+1] =='\r'))
		{
			if (i + 3 == strlen(content))
			{
				printf("None Entity Content\n");
				break;
			}
			for (j = 0; j < number - i - 3; j++)
				entity_content[j] = content[i + 3 + j];
			entity_content[j] = '\0';
			printf("Entity Content: \n");
			for (i = 0; i < j; i++)
			{
				printf("%s", char_to_ascii(entity_content[i]));
			}
			printf("\n");
			break;
		}
		k = 0;
	}
}
//The following func is an analysis of the data received by thr WEB svr
void parse_server_data(char content[], int number)
{
	char temp[1024];
	char str1[1024];
	char str2[1024];
	char str3[1024];
	int i;
	int k;
	int j;
	char entity_content[1024];
	for (i = 0; i < strlen(content); i++)
	{
		if (content[i] != '\n')
		{
			k++;
			continue;
		}
		for (j = 0; j < k; j++)
			temp[j] = content[j + i -k];
		temp[j] = '\0';
		if (strstr(temp, "GET"))
		{
			printf("Request: ");
			printf("%s\n", temp);
			sscanf(temp, "%s %s %s", str1, str2, str3);
			printf("Command:%s\n", str1);
			printf("Resource:%s\n", str2);
			printf("HTTP Protocol Type:\n", str3);
		}
		if (strstr(temp, "Accept:"))
		{
			printf("Accept:%s\n", temp + strlen("Accept:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Referer:"))
		{
			printf("Referer:%s\n", temp + strlen("Referer:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Accept-Language"))
		{
			printf("Accept-Language:%s\n", temp + strlen("Accept-Language:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Accept-Encoding"))
		{
			printf("Accept-Encoding:%s\n", temp + strlen("Accept-Encoding:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "If-Modified-Since"))
		{
			printf("If-Modified-Since:%s\n", temp + strlen("If-Modified-Since;"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "If-None-Match"))
		{
			printf("If-None-Match%s\n", temp + strlen("If-None-Match"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "User-Agent"))
		{
			printf("User-Agent:%s\n", temp + strlen("User-Agent"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Host"))
		{
			printf("Host:%s\n", temp + strlen("Host:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Connection"))
		{
			printf("Connection:%s\n", temp + strlen("Connection:"));
			printf("%s\n", temp);
		}
		if (strstr(temp, "Cookie"))
		{
			printf("Cookie:%s\n", temp + strlen("Cookie:"));
			printf("%s\n", temp);
		}
		//Get Entity Content
		if ((content[i] == '\n') && (content[i + 1] == '\r') && (content[i + 2] == '\n'))
		{
			if (i + 3 == strlen(content))
			{
				printf("None Entity Content\n");
				break;
			}
			for (j = 0; j < strlen(content) -i -3; j++)
				entity_content[j] = content[i + 3 +j];;
			entity_content[j] = '\0';
			printf("Entity Content\n");
			printf("%s", entity_content);
			printf("\n");
			break;
		}
		k = 0;
	}
}
//The following is callback func, used to analysis the HTTP layer proc
void http_protocol_callback(struct tcp_stream* tcp_http_connection, void** param)
{
	char address_content[1024];
	char content[65535];
	char content_urgent[65535];
	struct tuple4 ip_and_port = tcp_http_connection->addr;
	strcpy(address_content, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
	sprintf(address_content + strlen(address_content, ": %i", ip_and_port.source));
	strcat(address_content, " <----> ");
	strcat(address_content, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
	sprintf(address_content + strlen(address_content), ": %i", ip_and_port.dest);
	strcat(address_content, "\n");
	if (tcp_http_connection->nids_state == NIDS_JUST_EST)
	{
		if (tcp_http_connection->addr.dest != 80)	//Capture HTTP layer proc onlu
		{
			return;
		}
		tcp_http_connection->client.collect++;		//data recved by browser
		tcp_http_connection->server.collect++;		//data recved by Web svr
		printf("\n\n\n=============================================");
		printf("%s Connecting... \n", address_content);
		return;
	}
	if (tcp_http_connection->nids_state == NIDS_CLOSE)
	{
		printf("----------------------------------\n");
		printf("%s Connection close normaly... \n", address_content);
		return;
	}
	if (tcp_http_connection->nids_state == NIDS_RESER)
	{
		printf("----------------------------------\n");
		printf("%s Connection closed by RST... \n", address_content);
		return;
	}
	if (tcp_http_connection->nids_state == NIDS_DATA)
	{
		struct half_stram* hlf;
		if (tcp_http_connection->client.count_new)	//data recved by browser
		{
			hlf = &tcp_http_connection->client;		//hlf means the data recved by browser
			strcpy(address_content, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
			sprintf(address_content + strlen(address_content), ": %i", ip_and_port.source);
			strcat(address_content, " <---- ");
			strcat(address_content, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
			sprintf(address_content + strlen(address_content), ": %i", ip_and_port.dest);
			strcat(address_content, "\n");
			printf("\n");
			printf("%s", address_content);
			printf("Browser receiving data... \n");
			printf("\n");
			memcpy(content, hlf->data, hlf->count_new);
			content[hlf->count_new] = '\0';
			parse_client_data(content, hlf->count_new);
			//Analysis the data recved by browser
		}
		else
		{
			hlf = &tcp_http_connection->server;		//hlf means Web server TCP connection pin
			strcpy(address_content, inet_ntoa(*((struct in_addr *) &(ip_and_port.saddr))));
			sprintf(address_content + strlen(address_content), ": %i", ip_and_port.source);
			strcat(address_content, " ----> ");
			strcat(address_content, inet_ntoa(*((struct in_addr *) &(ip_and_port.daddr))));
			sprintf(address_content + strlen(address_content), ": %i", ip_and_port.dest);
			strcat(address_content, "\n");
			printf("\n");
			printf("%s", address_content);
			printf("Server receiving data... \n");
			printf("\n");
			memcpy(content, hlf->data, hlf->count_new);
			content[hlf->count_new] = '\0';
			parse_server_data(content, hlf->count_new);
			//Analysis the data recved by Web svr
		}
	}
	return;
}
//Main func
void main()
{
	if (!nids_init())
	{
		printf("ERROR: %s\n", nids_errbuf);
		exit(1);
	}
	nids_register_tcp(http_protocol_callback);		//reg callback func
	nids_run();							
}