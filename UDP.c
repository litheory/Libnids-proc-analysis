#include "nids.h" 
//Data struct of UDP's Header 
struct udp_header
{
	unsigned short udp_source_port;				//src port
	unsigned short udp_destination_port			//dst port
	unsigned short udp_length;					//len
	unsigned short udp_checksum;				//checksum
};
//Data struct of IP's Header
struct ip_header
{
	#if defined(WORDS_BIGENDIAN)
		unsigned char ip_version : 4,			//ip ver
			ip_header_length : 4;				//header len
	#else
		unsigned char ip_header_length : 4,
			ip_version : 4;
	#endif
		unsigned char ip_tos;					//type of server
		unsigned short ip_length;				//total len
		unsigned short ip_id;					//ip id
		unsigned short ip_off;					//id and offset
		unsigned char ip_ttl;					//time to live
		unsigned char ip_protocol;				//proc
		unsigned short ip_checksum;				//checksum
		struct in_addr ip_source_address;		//src ip addr
		struct in_addr ip_destination_address;	//dst ip addr
};
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
		*string++ = ch;
	}
	else
	{
		*string++ = '.';
	}
	*string = 0;
	return ascii_string;
}
//Down here is func of ananysis UDP
void udp_protocol_packet_callback(u_char* packet_content)
{
	struct udp_header* udp_protocol;
	u_short source_port;
	u_short destination_port;
	u_short length;
	udp_protocol = (struct udp_header *)(packet_content + 20);		//Get UDP packet data
	source_port = ntohs(udp_protocol->udp_source_port);			//Get src port
	destination_port = ntohs(udp_protocol->udp_destination_port);	//Get dst port
	length = ntohs(udp_protocol->udp_length);						//Get data len
	printf("------------UDP layer protocol Header----------\n");
	printf("Source port:%d\n", source_port);
	printf("Destination port:%d\n", destination_port);
	switch (destination_port)			//Get port and ensure the upper layer porc type
	{
		case 138:
			printf("NETBIOS Dataqram Service\n");break;
		case 137:
			printf("NETBIOS Name Service\n");break;
		case 139:
			printf("NETBIOS Session Service\n");break;
		case 53:
			printf("name-domain server\n");break;
		default:
			break;
	}
	printf("Length:%d\n", length);
	printf("CheckSum:%d\n", ntohs(udp_protocol->udp_checksum));	//Get CheckSum	
}
//Down here is func of analysis IP
void ip_protocol_packet_callback(u_cahr* packet_content)
{
	struct ip_header* ip_protocol;
	u_int header_length;
	u_int offset;
	u_char tos;
	unsigned short checksum;
	printf("----------IP layer protocol Header----------\n");
	ip_protocol = (struct ip_header *) (packet_content);			//Get IP packet data
	checksum = ntohs(ip_protocol->ip_checksum);					//Get CheckSum
	header_length = ip_protocol->ip_header_length * 4;			//Get Header len
	tos = ip_protocol->ip_tos;									//Get type of servcie
	offset = ntohs(ip_protocol->ip_off);							//Get id and offset
	printf("Vesion of IP:%d\n", ip_protocol->ip_version);
	printf("Header Length:%d\n", header_length);
	printf("Type of Service:%d\n", tos);
	printf("Total Length:%d\n", ntohs(ip_protocol->ip_length));
	printf("ID:%d\n", ntohs(ip_protocol->ip_id));
	printf("Offset:%d\n", (offset & 0x1fff) * 8);
	printf("Time to Live:%d\n", ip_protocol->ip_ttl);
	printf("Protocol Type:%d\n", ip_protocol->ip_protocol);
	switch (ip_protocol->ip_protocol)
	{								//Judge upper layer proc type	
		case 6:
			printf("Upper Layer Protocol is TCP\n");break;
		case 17:
			printf("Upper Layer Protocol is UDP\n");break;
		case 1:
			printf("Upper Layer Protocol is ICMP\n");break;
		default:
			break;
	}
	printf("Checksum:%d\n", checksum);
	printf("Source IP Address:%s\n", inet_ntoa(ip_protocol->ip_source_address));
																	//Get src ip addr
	printf("Destination IP Address:%s\n", inet_ntoa(ip_protocol->ip_destination_address));
																	//Get dst ip addr
	switch (ip_protocol->ip_protocol)
	{
		case 17:
			udp_protocol_packet_callback(packet_content);break;		//Calling the func of analysis UDP layer proc
		default:
			break;
	}
}
//Down here is callback func, this func will reg in nids_register_udp()
void udp_callback(struct tuple4* addr, char* buf, int len, struct ip* iph)
{
	int i;
	char content[65535];
	char content_urgent[65535];
	char tcp_content[65535];
	char buffer[1024];
	strcpy(buffer, inet_ntoa(*((struct in_addr *) &(addr->saddr))));
	sprintf(buffer + strlen(buffer), ": %i", addr->source);
	strcat(buffer, " -> ");
	strcat(buffer, inet_ntoa(*((struct in_addr *) &(addr->daddr))));
	sprintf(buffer + strlen(buffer), ": %i", addrr->dest);
	strcat(buffer, "\n");
	printf("-----------------------BEGIN----------------------\n");
	printf("%s\n", buffer);
	ip_protocol_packet_callback(iph);								//Calling the func of analysis IP layer proc
	printf("--------------UDP data packet conetent-------------\n"); //Output UDP load data conetent
	for (i = 0; i < len; i++)	
	{
		if (i % 50 == 0)
		{
			printf("\n");
		}
		printf("%s", char_to_ascii(buf[i]));
	}
	printf("\n");
	printf("-------------------------END----------------------\n");
	printf("\n");
	return;
}
//Main func
void main()
{
	if (!nids_init())								//Init Libnids
	{
		printf("%s\n", nids_errbuf);
		exit(1);
	}
	nids_register_udp(udp_callback);				//Reg callback func
	nids_run();										//Loop to capture datapacket
}											