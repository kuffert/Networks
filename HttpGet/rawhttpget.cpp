#include <stdio.h>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <map>
#include <vector>
#include <iterator>
#include <algorithm>


int openSendSock();
int openReceiveSock();
int getDestinationInfo();
char* findLocalIP(); 
unsigned short calculateTCPChecksum(tcphdr* tcph, char* sourceIP, char* packetData);
std::string parseHostFromURL(std::string url);
std::string parseExtensionFromURL(std::string url);
std::string parseFileNameFromURL(std::string url);

void constructHandshakeSYNPacket(char* synPacket, struct iphdr* syniph, tcphdr* syntcph, char* sourceIP, unsigned int dest, int sourceport);
void constructHandshakeACKPacket(char* ackPacket, struct iphdr* ackiph, struct tcphdr* acktcph, char* sourceIP, tcphdr* tcphResponse);
void constructGetRequestPacket(char* getPacket, struct iphdr* getiph, struct tcphdr* gettcph, char* getRequest, char* sourceIP, tcphdr* tcphResponse);
void constructACKPacket(char* ackPacket, struct iphdr* ackiph, struct tcphdr* acktcph, char* sourceIP, tcphdr* tcphResponse, int receivedPacketDataSize);
void constructFINPacket(char* finPacket, struct iphdr* finiph, struct tcphdr* fintcph, char* sourceIP, tcphdr* tcphResponse);

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short checksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes>1) 
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) 
	{
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return(answer);
}


std::string url;
std::string urlhost;
std::string urlextension;
std::string filename;
struct hostent *dest;
struct hostent *source;
sockaddr_in addressStruct;
sockaddr_in sourcePort;
fd_set socketSet;

int sendSocket;
int receiveSocket;

int cwnd = 1;

int main(int argc, char **argv) {
// need to do perform http get on the argument url using raw sockets TCP and IP
	findLocalIP();
	if (argc != 2)
	{
		printf("Error: invalid number of args\n");
        return 0;
	}
	url = argv[1];
	urlhost = parseHostFromURL((char*)url.c_str());
	urlextension = parseExtensionFromURL((char*)url.c_str());
	filename = parseFileNameFromURL((char*)url.c_str());
	//printf("%s\n", urlhost.c_str());
	//printf("%s\n", filename.c_str());

	// Hardsetting the source IP for the time being 
	char sourceIP[32];
	strcpy(sourceIP, findLocalIP());
	memset(&sourcePort, 0, sizeof(sockaddr_in));
	srand(time(0));
	sourcePort.sin_port = rand() % 65535;

	// Address resolution
	int infoResult = getDestinationInfo();
	if (infoResult < 0)
	{
        // If the host cannot be found, exit the program.
        printf("Error: host not found. Exiting.\n");
		return 0;
	}

	// Values for setting options
	int one = 1;
	const int *val = &one;

	// Set up receiving socket
	receiveSocket = openReceiveSock();

	//Set up the sending socket
	sendSocket = openSendSock();
	FD_ZERO(&socketSet);
	FD_SET(sendSocket, &socketSet);
	struct timeval timeout;
	timeout.tv_sec = 5;
	fcntl(sendSocket, F_SETFL, O_NONBLOCK);

	// Tells the Kernel that we will be giving the IP header along with this packet.
	int setsockoptOutcome = setsockopt(sendSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
	if (setsockoptOutcome < 0)
	{
		printf("Error setting socket options to announce Ip header is given with this packet.");
		return 0;
	}

	// BEGIN HANDSHAKE -------------------------------//
	printf("--HANDSHAKE STARTED--\n");
	// 1.) Construct initial SYN packet
	char synPacket[2000];
	memset(synPacket, 0, 2000);
	struct iphdr *iph = (struct iphdr *) synPacket;
	struct tcphdr *tcph = (struct tcphdr *) (synPacket + sizeof(struct ip));
	constructHandshakeSYNPacket(synPacket, iph, tcph, sourceIP, addressStruct.sin_addr.s_addr, sourcePort.sin_port);

	// Send the SYN packet
	int synPacketSendResult = sendto(sendSocket, synPacket, iph->tot_len, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct));
	if (synPacketSendResult < 0)
	{ 
		printf("Error sending SYN packet.\n");
		printf("%d\n", errno);
		return 0;
	}

	// Read back the server's response
	char buffer[2000];
	memset(buffer, 0, 2000);
	int receiveResult = recv(receiveSocket, buffer, 2000, 0);
	if (receiveResult < 0)
	{
		printf("Failed to recieve SYN ACK packet\n");
		printf("%d\n", errno);
		return 0;
	}

	// 2.) Construct SYN ACK response packet from buffer
	unsigned short iphdrlen;
	struct iphdr *iphResponse = (struct iphdr *) buffer;
	iphdrlen = iphResponse->ihl * 4;
	struct tcphdr *tcphResponse = (struct tcphdr*) (buffer + iphdrlen);

	// 2.1.) Ensure the incoming packet was meant for this destination
	if (!(tcph->source == tcphResponse->dest && tcph->dest == tcphResponse->source && tcphResponse->syn == 1 && tcphResponse->ack == 1))
	{
		printf("Packet was not a SYN ACK Packet. Exiting (SHOULD RETRY)\n");
		return 0;
	}

	// 3.) Construct ACK handshake packet
	char ackPacket[2000];
	memset(ackPacket, 0, 2000);
	struct iphdr *ackiph = (struct iphdr *) ackPacket;
	struct tcphdr *acktcph = (struct tcphdr *) (ackPacket + sizeof(struct ip));
	constructHandshakeACKPacket(ackPacket, ackiph, acktcph, sourceIP, tcphResponse);

	int ackPacketSendResult = sendto(sendSocket, ackPacket, ackiph->tot_len, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct));

	if (ackPacketSendResult < 0)
	{
		printf("Error sending ACK packet.\n");
		printf("%d\n", errno);
		return 0;
	}

	// HANDSHAKE COMPLETED ----- //
	printf("--HANDSHAKE COMPLETED--\n");

	// -- SENDING GET REQUEST PACKET ---- //
	printf("--SUBMITTING GET REQUEST--\n");
	char getPacket[2000];
	memset(getPacket, 0, 2000);
	char * getRequest;
	getRequest = getPacket + sizeof(struct iphdr) + sizeof(struct tcphdr);
	char getRequestString[] = "";
	// this case is breaking for some reason, going to cat a "/" onto ones with no extension to hack it together for now
	if (strcmp(urlextension.c_str(), "") == 0)
	{
		printf("the case where there is no extension = %s\n", urlhost.c_str());
		sprintf(getRequestString, "GET HTTP/1.0\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", urlhost.c_str());
	}
	else
	{	
		printf("the case where there IS an extension\n");
		sprintf(getRequestString, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", urlextension.c_str(), urlhost.c_str());
	}
	printf("%s\n", getRequestString);
	strcpy(getRequest, getRequestString);
	struct iphdr*getiph = (struct iphdr *) getPacket;
	struct tcphdr *gettcph = (struct tcphdr *) (getPacket + sizeof(struct ip));
	constructGetRequestPacket(getPacket, getiph, gettcph, getRequest, sourceIP, tcphResponse);
	int getRequestResult = sendto(sendSocket, getPacket, getiph->tot_len, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct));
	if (getRequestResult < 0)
	{
		printf("Error sending GET request packet.\n");
		printf("%d\n", errno);
		return 0;
	}

	//-- GET REQUEST SENT --//
	printf("--GET REQUEST COMPLETED--\n");

	// default timeout criteria
  	struct timeval timeVal;
  	timeVal.tv_sec = 60;

	// Stop downloading data after a FIN flag is recieved.
	bool finReceived = false;

  	// construct the fd_set for select in order to manage timeouts for the download
  	fd_set recvSocks;
  	FD_ZERO(&recvSocks);
    FD_SET(receiveSocket, &recvSocks);

	// 2.	while (1) [no ACK in > 1 minute = lost packet = retransmit]
	char lastTransmittedPacket[10000];
	memset(lastTransmittedPacket, 0, 10000);
	memcpy(lastTransmittedPacket, getPacket, sizeof(getPacket));
	size_t lastTransmittedIPTotalLen = getiph->tot_len;

	char finResponsePacket[10000];
	memset(finResponsePacket, 0, 10000);
	struct iphdr *finResponseiph;
	struct tcphdr *finResponsetcph;
	std::vector<int> acked;
	std::vector<int> unacked;
	std::map<unsigned int, std::string> readPackets;
	while (1)
	{
		// wait to receive, or for a timeout
        if (select(receiveSocket + 1, &recvSocks, NULL, NULL, &timeVal)) 
        {
        	char packetBuffer[10000];
			memset(packetBuffer, 0, 10000);
			int receiveResult = recv(receiveSocket, packetBuffer, 10000, 0);
			if (receiveResult < 0)
			{
				printf("Failed to recieve SYN ACK packet\n");
				printf("%d\n", errno);
				return 0;
			}
            // reverse engineer IP and TCP headers
            unsigned short download_iphdrlen;
			struct iphdr *download_iphResponse = (struct iphdr *) packetBuffer;
			download_iphdrlen = download_iphResponse->ihl * 4;
			struct tcphdr *download_tcphResponse = (struct tcphdr*) (packetBuffer + download_iphdrlen);
			char *packetData = packetBuffer + download_iphdrlen + sizeof(struct tcphdr);

			// the server's should send seq = MY_LAST_ACK
            unsigned short last_iphdrlen;
			struct iphdr *last_iphResponse = (struct iphdr *) lastTransmittedPacket;
			last_iphdrlen = last_iphResponse->ihl * 4;
			struct tcphdr *last_tcphResponse = (struct tcphdr*) (lastTransmittedPacket + last_iphdrlen);

			unsigned long payload = ntohs(download_iphResponse->tot_len) - ((download_iphResponse->ihl + download_tcphResponse->doff) * 4);

			// verify checksum
			// STILL NEED TO VERIFY THE TCP CHECKSUM
			if ( checksum((unsigned short *)download_iphResponse, download_iphResponse->ihl * 4) ) /* ||
				 (calculateTCPChecksum(download_tcphResponse, sourceIP, packetBuffer) != download_tcphResponse->check) )*/
			{
				// one of the checksum verifications failed
				printf("--CHECKSUM VERIFICATION FAILED\n");
			}

			// if fin flag is read, break out of flow to teardown connection
			if (download_tcphResponse->fin)
			{
				finResponseiph = (struct iphdr *) finResponsePacket;
				finResponsetcph = (struct tcphdr *) (finResponsePacket + sizeof(struct ip));
				constructFINPacket(finResponsePacket, finResponseiph, finResponsetcph, sourceIP, download_tcphResponse);
				printf("--FIN RECEIVED - TIME TO TEAR DOWN CONNECTION--\n");
				break;
			}

			//printf("inserting packet %u\n%s\n", download_tcphResponse->seq, packetData);
			if (strlen(packetData) > 0)
			{
				std::string dataString(packetData);
				if (readPackets.find(download_tcphResponse->seq) == readPackets.end())
				{
					readPackets[download_tcphResponse->seq] = dataString;
				}
			/*
				bool inserted = readPackets.insert(std::make_pair(download_tcphResponse->seq, dataString)).second;
				if (!inserted)
				{
					printf("Failure to insert\n");
				}
				else
				{
					//printf("Inserted:%u\n", download_tcphResponse->seq);
					printf("Inserted correctly: %u\n", download_tcphResponse->seq);

				}
				*/
			}
			// as long as there's an ack, accept the data (just try that if you're not making progress)

			// if the payload is empty and this is NOT a fin packet, no need to ack or write
			if (!payload)
			{
				continue;
			}
			// if cwnd is not at max, increment
			if (cwnd < 1000)
			{
				cwnd++;
			}

			// build and send ack packet
			char ackResponsePacket[10000];
			memset(ackResponsePacket, 0, 10000);
			struct iphdr *ackResponseiph = (struct iphdr *) ackResponsePacket;
			struct tcphdr *ackResponsetcph = (struct tcphdr *) (ackResponsePacket + sizeof(struct ip));
			int downloadedPacketPayloadSize = ntohs(download_iphResponse->tot_len) - ((download_iphResponse->ihl + download_tcphResponse->doff) * 4);
			constructACKPacket(ackResponsePacket, ackResponseiph, ackResponsetcph, sourceIP, download_tcphResponse, downloadedPacketPayloadSize);

			if (sendto(sendSocket, ackResponsePacket, ackResponseiph->tot_len, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct)) < 0)
			{
				printf("Error sending ACK packet.\n");
				printf("%d\n", errno);
				return 0;
			}
			//printf("Adding %d to acked\n", download_tcphResponse->seq + htonl(downloadedPacketPayloadSize));
			acked.push_back(download_tcphResponse->seq);

			memset(lastTransmittedPacket, 0, 10000);
			memcpy(lastTransmittedPacket, ackResponsePacket, sizeof(ackResponsePacket));
			size_t lastTransmittedIPTotalLen = ackResponseiph->tot_len;
		}
		// in the case of a timeout
		else
		{
			printf("--TIMEOUT - MUST RESTRANSMIT--\n");
			// DOES THE FLOORED CWND NEED TO BE IN THE RETRANSMITTED PACKET?
			cwnd = 1;
			// this covers the case where we never got a response from our last packet
			// how would we manage long responses FROM the server? also with select?
			if (sendto(sendSocket, lastTransmittedPacket, lastTransmittedIPTotalLen, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct)) < 0)
			{
				printf("Error retransmitting packet.\n");
				printf("%d\n", errno);
				return 0;
			}
			timeVal.tv_sec = 60;
		}
	}

	// correctly tear down connection
	// fin
	printf("--TEARING DOWN CONNECTION--\n");
	if (sendto(sendSocket, finResponsePacket, finResponseiph->tot_len, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct)) < 0)
	{
		printf("Error retransmitting packet.\n");
		printf("%d\n", errno);
		return 0;
	}

/*	this was thinking that we had to send one last ack but I guess we don't?
	//hear server's ack
	char serverAck[2000];
	memset(serverAck, 0, 2000);
	int sercerAckRecv = recv(receiveSocket, serverAck, 2000, 0);
	if (sercerAckRecv < 0)
	{
		printf("Failed to recieve ACK packet\n");
		printf("%d\n", errno);
		return 0;
	}

	unsigned short finalAck_iphdrlen;
	struct iphdr *finalAck_iphResponse = (struct iphdr *) serverAck;
	finalAck_iphdrlen = finalAck_iphResponse->ihl * 4;
	struct tcphdr *finalAck_tcphResponse = (struct tcphdr*) (serverAck + finalAck_iphdrlen);
	char *packetData = serverAck + finalAck_iphdrlen + sizeof(struct tcphdr);

	char finalAck[2000];
	memset(finalAck, 0, 2000);
	struct iphdr *finalAckiph = (struct iphdr *) ackPacket;
	struct tcphdr *finalAcktcph = (struct tcphdr *) (ackPacket + sizeof(struct ip));
	constructHandshakeACKPacket(finalAck, finalAckiph, finalAcktcph, sourceIP, finalAck_tcphResponse);
	printf("The last ack from the server should be ack=\n");
	// send the final closing ack
	if (sendto(sendSocket, finalAck, finalAckiph->tot_len, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct)) < 0)
	{
		printf("Error retransmitting packet.\n");
		printf("%d\n", errno);
		return 0;
	}
*/

	//FILE *file = fopen(filename.c_str(), "a+");
	// iterate through the map of read packets
	//std::string temp = "";
	char temp[10000];
	std::map<unsigned int, std::string>::iterator it = readPackets.begin();
	printf("PLEASE HELP ME GOD I WANT TO DIE : %u\n", it->first);
	for (it = readPackets.begin(); it != readPackets.end(); it++)
	{
		strcat(temp, it->second.c_str());
		printf("Pulling:%u\n", it->first);
		//printf("%s\n", it->second.c_str());
		//fprintf(file, "%s", it->second);
	}
	char finalPrint[10000];
	strncpy(finalPrint, temp, sizeof(finalPrint));
	printf("%s\n", temp);
	FILE *file = fopen(filename.c_str(), "w");
	fprintf(file, "%s", temp);
	fclose(file);


	printf("--MAIN FUNCTION HAS ENDED--\n");
	close(sendSocket);
	close(receiveSocket);
	return 0;
}

// Open the sending raw socket
int openSendSock()
{
    int rawSockSend = -1;
    rawSockSend = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(rawSockSend == -1)
    {
        printf("Failed to create send socket.\n");
        exit(1);
    }
    return rawSockSend;
}

// Opens the reciever socket
int openReceiveSock()
{
	int rawSocketRecieve = -1;
	rawSocketRecieve = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (rawSocketRecieve == -1)
	{
		printf("Failed to create receiver socket. Exiting.\n");
		exit(1);
	}
	return rawSocketRecieve;
}

// Retreives the destination information
int getDestinationInfo() 
{
	dest = gethostbyname(urlhost.c_str());
    if (dest == NULL)
    {
        return -1;
    }
    addressStruct.sin_port = htons(80);
    addressStruct.sin_family = AF_INET;
    addressStruct.sin_addr.s_addr = (u_long)dest->h_addr;
    bcopy((char *)dest->h_addr, (char *)&addressStruct.sin_addr.s_addr, dest->h_length);
    return 0;
}

// Discover local IP address (CURRENTLY DOES NOT WORK)
char* findLocalIP()
{
	FILE *file;
    char line[100] , *interface , *gateway;
     
    file = fopen("/proc/net/route" , "r");
     
    while(fgets(line , 100 , file))
    {
        interface = strtok(line , " \t");
        gateway = strtok(NULL , " \t");
         
        if(interface!=NULL && gateway!=NULL)
        {
            if(strcmp(gateway , "00000000") == 0)
            {
                break;
            }
        }
    }
	//which family do we require , AF_INET or AF_INET6
    int fm = AF_INET;
    struct ifaddrs *ifaddr, *ifa;
    int family , s;
    char host[NI_MAXHOST];
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    // iterate through the addresses
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
            continue;
        }
        family = ifa->ifa_addr->sa_family;
        if(strcmp(ifa->ifa_name , interface) == 0)
        {
            if (family == fm)
            {
                s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) , host , NI_MAXHOST , NULL , 0 , NI_NUMERICHOST);
                 
                if (s != 0)
                {
                    printf("getnameinfo() failed: %s\n", gai_strerror(s));
                    exit(EXIT_FAILURE);
                }
                 
            }
        }
    }
    freeifaddrs(ifaddr);
    return host;
}

// parse the host from the given url
// NOTE: ONLY HANDLES REGULAR .COMS RIGHT NOW
std::string parseHostFromURL(std::string url)
{
	std::string host;
	int comIndex = url.find(".com");
	std::string hostName = url.substr(0, comIndex);
	if (hostName.find("http://") != std::string::npos)
	{
		// 6 below is strlen("http://") - 1
		host = hostName.substr(6, strlen(hostName.c_str()) - 1);
	}
	host = hostName + ".com";
	return host;
}

// parse the extension from the given url
std::string parseExtensionFromURL(std::string url)
{
	std::string extension = "";
	if (url.find("/") == std::string::npos)
	{
		return extension + "/";
	}
	int comIndex = url.find(".com");
	extension = url.substr((comIndex + 4), (strlen(url.c_str()) - 1));
	return extension;
}

// parse the file name and ext from url
std::string parseFileNameFromURL(std::string url)
{
	if ((url[strlen(url.c_str()) - 1] == '/') || (url.find("/") == std::string::npos))
	{
		return "index.html";
	}
	int indexOfLastSlash = url.find_last_of("/");
	return url.substr(indexOfLastSlash + 1, strlen(url.c_str()) - 1);
}
// Calculates the checksum for a TCP packet
unsigned short calculateTCPChecksum(tcphdr* tcph, char* sourceIP, char* packetData)
{
	struct pseudo_header psh;
	psh.source_address = inet_addr(sourceIP);
	psh.dest_address = addressStruct.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(packetData));

	int phsize = sizeof(struct pseudo_header);
	int tcphdrsize = sizeof(struct tcphdr);
	int psize = phsize + tcphdrsize + strlen(packetData);

	char * pseudogram =(char *) malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(packetData));

	return checksum((unsigned short*)pseudogram, psize);
}

// Builds the initial SYN handshake packet
void constructHandshakeSYNPacket(char* synPacket, struct iphdr* syniph, tcphdr* syntcph, char* sourceIP, unsigned int dest, int sourceport)
{
	syniph->ihl = 5;
	syniph->version = 4;
	syniph->tos = 0;
	syniph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	syniph->frag_off = 0;
	syniph->ttl = 255;
	syniph->protocol = IPPROTO_TCP;
	syniph->saddr = inet_addr(sourceIP);
	syniph->daddr = dest;
	syniph->check = 0;
	syniph->check = checksum((unsigned short *)synPacket, syniph->tot_len);

	syntcph->source = htons(sourceport);
	syntcph->dest = htons(80);
	syntcph->seq = htonl(random());// rand() % 4000000000);
	syntcph->ack_seq = htonl(0);
	syntcph->doff = 5; 
	syntcph->fin = 0;
	syntcph->syn = 1;
	syntcph->rst = 0;
	syntcph->psh = 0;
	syntcph->ack = 0;
	syntcph->urg = 0;
	syntcph->window = htons(64240);
	syntcph->check = 0;
	syntcph->urg_ptr = 0;

	struct pseudo_header synpsh;
	synpsh.source_address = inet_addr(sourceIP);
	synpsh.dest_address = addressStruct.sin_addr.s_addr;
	synpsh.placeholder = 0;
	synpsh.protocol = IPPROTO_TCP;
	synpsh.tcp_length = htons(sizeof(struct tcphdr));

	int phsize = sizeof(struct pseudo_header);
	int tcphdrsize = sizeof(struct tcphdr);
	int psize = phsize + tcphdrsize;

	char * pseudogram = (char *)malloc(psize);
	memcpy(pseudogram, (char*)&synpsh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), syntcph, sizeof(struct tcphdr));

	syntcph->check = checksum((unsigned short*)pseudogram, psize);
}

// Buulds the ACK response handshake packet
void constructHandshakeACKPacket(char* ackPacket, struct iphdr* ackiph, struct tcphdr* acktcph, char* sourceIP, tcphdr* tcphResponse)
{
	ackiph->ihl = 5;
	ackiph->version = 4;
	ackiph->tos = 0;
	ackiph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	ackiph->frag_off = 0;
	ackiph->ttl = 255;
	ackiph->protocol = IPPROTO_TCP;
	ackiph->saddr = inet_addr(sourceIP);
	ackiph->daddr = addressStruct.sin_addr.s_addr;
	ackiph->check = 0;
	ackiph->check = checksum((unsigned short *)ackPacket, ackiph->tot_len);

	acktcph->source = tcphResponse->dest;
	acktcph->dest = tcphResponse->source;
	acktcph->seq = tcphResponse->ack_seq;
	acktcph->ack_seq = tcphResponse->seq + htonl(1);
	acktcph->doff = 5;  //tcp header size
	acktcph->fin = 0;
	acktcph->syn = 0;
	acktcph->rst = 0;
	acktcph->psh = 0;
	acktcph->ack = 1;
	acktcph->urg = 0;
	acktcph->window = htons(64240);
	acktcph->check = 0;
	acktcph->urg_ptr = 0;

	struct pseudo_header ackpsh;
	ackpsh.source_address = inet_addr(sourceIP);
	ackpsh.dest_address = addressStruct.sin_addr.s_addr;
	ackpsh.placeholder = 0;
	ackpsh.protocol = IPPROTO_TCP;
	ackpsh.tcp_length = htons(sizeof(struct tcphdr));

	int phsize = sizeof(struct pseudo_header);
	int tcphdrsize = sizeof(struct tcphdr);
	int psize = phsize + tcphdrsize;
	
	char * pseudogram = (char *)malloc(psize);
	memcpy(pseudogram, (char*)&ackpsh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), acktcph, sizeof(struct tcphdr));

	acktcph->check = checksum((unsigned short*)pseudogram, psize);

	/*
	int sso = sendto(sendSocket, ackPacket, ackiph->tot_len, 0, (struct sockaddr *) &addressStruct, sizeof(addressStruct));

	if (sso < 0)
	{
		printf("Error sending packet.\n");
		printf("%d\n", errno);
		return;
	}

	printf("Should hae sent an ack packet request");
	*/
}

// Sends the get request to download the url
void constructGetRequestPacket(char* getPacket, struct iphdr* getiph, struct tcphdr* gettcph, char* getRequest, char* sourceIP, tcphdr* tcphResponse)
{
	getiph->ihl = 5;
	getiph->version = 4;
	getiph->tos = 0;
	getiph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(getRequest);
	getiph->frag_off = 0;
	getiph->ttl = 255;
	getiph->protocol = IPPROTO_TCP;
	getiph->saddr = inet_addr(sourceIP);
	getiph->daddr = addressStruct.sin_addr.s_addr;
	getiph->check = 0;
	getiph->check = checksum((unsigned short *)getPacket, getiph->tot_len);

	// make TCP Packet;
	gettcph->source = tcphResponse->dest;
	gettcph->dest = tcphResponse->source;
	gettcph->seq = tcphResponse->ack_seq;
	gettcph->ack_seq = tcphResponse->seq + htonl(1);
	gettcph->doff = 5;  //tcp header size
	gettcph->fin = 0;
	gettcph->syn = 0;
	gettcph->rst = 0;
	gettcph->psh = 1;
	gettcph->ack = 1;
	gettcph->urg = 0;
	gettcph->window = htons(64240);
	gettcph->check = 0;
	gettcph->urg_ptr = 0;

	struct pseudo_header getpsh;
	getpsh.source_address = inet_addr(sourceIP);
	getpsh.dest_address = addressStruct.sin_addr.s_addr;
	getpsh.placeholder = 0;
	getpsh.protocol = IPPROTO_TCP;
	getpsh.tcp_length = htons(sizeof(struct tcphdr) + strlen(getRequest));

	int phsize = sizeof(struct pseudo_header);
	int tcphdrsize = sizeof(struct tcphdr);
	int psize = phsize + tcphdrsize + strlen(getRequest);

	char * pseudogram = (char *)malloc(psize);
	memcpy(pseudogram, (char*)&getpsh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), gettcph, sizeof(struct tcphdr) + strlen(getRequest));

	gettcph->check = checksum((unsigned short*)pseudogram, psize);

}

// Builds the ACK response packet for the download TCP flow
void constructACKPacket(char* ackPacket, struct iphdr* ackiph, struct tcphdr* acktcph, char* sourceIP, tcphdr* tcphResponse, int receivedPacketDataSize)
{
	ackiph->ihl = 5;
	ackiph->version = 4;
	ackiph->tos = 0;
	ackiph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	ackiph->frag_off = 0;
	ackiph->ttl = 255;
	ackiph->protocol = IPPROTO_TCP;
	ackiph->saddr = inet_addr(sourceIP);
	ackiph->daddr = addressStruct.sin_addr.s_addr;
	ackiph->check = 0;
	ackiph->check = checksum((unsigned short *)ackPacket, ackiph->tot_len);

	acktcph->source = tcphResponse->dest;
	acktcph->dest = tcphResponse->source;
	acktcph->seq = tcphResponse->ack_seq;
	acktcph->doff = 5;  //tcp header size
	// ack_seq = response seq + size of payload
	//printf("acking with ack of %d\n", htonl(receivedPacketDataSize));
	acktcph->ack_seq = tcphResponse->seq + htonl(receivedPacketDataSize);
	acktcph->fin = 0;
	acktcph->syn = 0;
	acktcph->rst = 0;
	acktcph->psh = 0;
	acktcph->ack = 1;
	acktcph->urg = 0;
	acktcph->window = htons(64240);
	acktcph->check = 0;
	acktcph->urg_ptr = 0;

	struct pseudo_header ackpsh;
	ackpsh.source_address = inet_addr(sourceIP);
	ackpsh.dest_address = addressStruct.sin_addr.s_addr;
	ackpsh.placeholder = 0;
	ackpsh.protocol = IPPROTO_TCP;
	ackpsh.tcp_length = htons(sizeof(struct tcphdr));

	int phsize = sizeof(struct pseudo_header);
	int tcphdrsize = sizeof(struct tcphdr);
	int psize = phsize + tcphdrsize;
	
	char * pseudogram = (char *)malloc(psize);
	memcpy(pseudogram, (char*)&ackpsh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), acktcph, sizeof(struct tcphdr));

	acktcph->check = checksum((unsigned short*)pseudogram, psize);
}

// Builds the ACK response packet for the download TCP flow
void constructFINPacket(char* finPacket, struct iphdr* finiph, struct tcphdr* fintcph, char* sourceIP, tcphdr* tcphResponse)
{
	finiph->ihl = 5;
	finiph->version = 4;
	finiph->tos = 0;
	finiph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	finiph->frag_off = 0;
	finiph->ttl = 255;
	finiph->protocol = IPPROTO_TCP;
	finiph->saddr = inet_addr(sourceIP);
	finiph->daddr = addressStruct.sin_addr.s_addr;
	finiph->check = 0;
	finiph->check = checksum((unsigned short *)finPacket, finiph->tot_len);

	fintcph->source = tcphResponse->dest;
	fintcph->dest = tcphResponse->source;
	fintcph->seq = tcphResponse->ack_seq;
	fintcph->doff = 5;  //tcp header size
	fintcph->ack_seq = tcphResponse->seq + htonl(1);
	fintcph->fin = 1;
	fintcph->syn = 0;
	fintcph->rst = 0;
	fintcph->psh = 0;
	fintcph->ack = 1;
	fintcph->urg = 0;
	fintcph->window = htons(64240);
	fintcph->check = 0;
	fintcph->urg_ptr = 0;

	struct pseudo_header finpsh;
	finpsh.source_address = inet_addr(sourceIP);
	finpsh.dest_address = addressStruct.sin_addr.s_addr;
	finpsh.placeholder = 0;
	finpsh.protocol = IPPROTO_TCP;
	finpsh.tcp_length = htons(sizeof(struct tcphdr));

	int phsize = sizeof(struct pseudo_header);
	int tcphdrsize = sizeof(struct tcphdr);
	int psize = phsize + tcphdrsize;
	
	char * pseudogram = (char *)malloc(psize);
	memcpy(pseudogram, (char*)&finpsh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), fintcph, sizeof(struct tcphdr));

	fintcph->check = checksum((unsigned short*)pseudogram, psize);
}