#include <stdio.h>
#include <stack>
#include <string>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sstream>
#include <ifaddrs.h>
#include <vector>
#include <iterator>
#include <algorithm>
#include <map>
#include <cmath>
#define pi 3.14159265358979323846
#define earthRadiusKm 6371.0

using namespace std;

//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd : 1; // recursion desired
	unsigned char tc : 1; // truncated message
	unsigned char aa : 1; // authoritive answer
	unsigned char opcode : 4; // purpose of message
	unsigned char qr : 1; // query/response flag

	unsigned char rcode : 4; // response code
	unsigned char cd : 1; // checking disabled
	unsigned char ad : 1; // authenticated data
	unsigned char z : 1; // its z! reserved
	unsigned char ra : 1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

int constructAndBindUDPSocket(int port);
int resolveHostname(std::string hostname);
void buildResponsePacket(DNS_HEADER* dns, char* buffer);
void buildResponsePacketv2(DNS_HEADER* dnsQuery, DNS_HEADER* dnsResponse, char* queryBuffer, char* buffer);
void encodeName(char*& buffer, const std::string& domain);
void encode2bytes(char*& buffer, unsigned int value);
void encodeCompressedName(char*& buffer, unsigned int value);
void encode4bytes(char*& buffer, unsigned long value);
void encodeIPAddr(char*& buffer, std::string ipaddr);
void resolveAllReplicaIPs();
void resolveReplicaIP(std::string hostname);
void selectIPAddressForClient();
int openGeoipRequestSocket();
std::string requestGeoipDataForHost(std::string ipAddr);
std::string grabString(std::string source, std::string beginning, std::string end);
float degreesToRadians(float degrees);
float haversineDistance(float latitude1, float longitude1, float latitude2, float longitude2);

int port;
std::string nameServer;

const unsigned int HDR_OFFSET = 12;

int requestSocket;
struct hostent *host;

fd_set socketSet;

struct sockaddr_in serverAddr;
struct sockaddr_in DNSAddress;

std::string serverIPAddress;

float clientLatitude;
float clientLongitude;
int geoipSocket;
struct sockaddr_in geoipAddr;
std::map<std::string, float> latitudeMap;
std::map<std::string, float> longitudeMap;

std::map<std::string, std::string> addressMap;
static int REPLICA_SERVER_COUNT = 9;
std::string selectedHostname;
std::string selectedIP;

int size = 0;

char geoipRequest[512];
char geoipGETresult[1000];

char queryBuffer[1000];
char queryName[256];
char tmp[256];

int main(int argc, char **argv) {
	if (argc != 5)
	{
		printf("Incorrect number of arguments. Please enter: -p <port> -n <name>\n");
		return 0;
	}
	port = atoi(argv[2]);
	nameServer = (argv[4]);

	printf("Starting server, binding to port %d ... ", port);
	requestSocket = constructAndBindUDPSocket(port);
	printf("Done\n");
	resolveAllReplicaIPs(); // Resolve all IPs

	// Set timeout value
	struct timeval timeVal;

	// Add request socket to receiving socket set
	fd_set recvSocks;
	FD_ZERO(&recvSocks);
	FD_SET(requestSocket, &recvSocks);

	fflush(stdout);
	// Server kicks on, continuously loops, receiving packets from clients and sending responses.
	while (1)
    {
        timeVal.tv_sec = 60;
        fd_set recvSocks;
        FD_ZERO(&recvSocks);
        FD_SET(requestSocket, &recvSocks);
 
		sockaddr_in clientAddr;
		memset(&clientAddr, 0, sizeof(sockaddr_in));
		socklen_t clientAddrSize = sizeof(clientAddr);

		memset(queryBuffer, 0, 1000);
		if (select(requestSocket + 1, &recvSocks, NULL, NULL, &timeVal))
		{

			int receivedData = recvfrom(requestSocket, queryBuffer, sizeof(queryBuffer), 0, (struct sockaddr*) &clientAddr, &clientAddrSize);
			printf("Client Addr: %s\n", inet_ntoa(clientAddr.sin_addr));
			if (receivedData < 0)
			{
				printf("Failed to receive data from client. Exiting.\n");
				printf("%d\n", errno);
				return 0;
            }
            
            std::string clientIP(inet_ntoa(clientAddr.sin_addr));
            openGeoipRequestSocket();
            std::string clientGeoipData = requestGeoipDataForHost(clientIP);
            close(geoipSocket);
            clientLatitude = (float)atof(grabString(clientGeoipData, "\"latitude\":", ",").c_str());
            clientLongitude = (float)atof(grabString(clientGeoipData, "\"longitude\":", ",").c_str());

			DNS_HEADER* dns = (DNS_HEADER*) queryBuffer;
			buildResponsePacket(dns, queryBuffer);

			char responseBuffer[size];
			memset(responseBuffer, 0, size);
			memcpy(responseBuffer, queryBuffer, size);
			if (sendto(requestSocket, responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr*) &clientAddr, clientAddrSize) < 0)
			{
				printf("Failed to send response. Exiting.\n");
				return 0;
			}
			printf("Response Sent.\n");
			fflush(stdout);
		}
        else
        {
            continue;
        }
	}

	close(requestSocket);
    close(geoipSocket);
	printf("Server shutting down.\n");
	return 0;
}

// Creates and binds the DNS server socket.
int constructAndBindUDPSocket(int port)
{
	int sock = -1;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		printf("Failed to open socket. Exiting.\n");
		exit(1);
	}

	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_port = htons(port);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	//htonl(inet_aton("127.0.0.1", &serverAddr.sin_addr));
	if (bind(sock, (struct sockaddr *) &serverAddr, sizeof(struct sockaddr_in)) < 0)
	{
		printf("Failed to bind socket. Exiting.\n");
		printf("%d\n", errno);
		close(sock);
		exit(1);
	}
	return sock;
}

// Attempts to resolve the given hostname
int resolveHostname(std::string hostname)
{
	host = gethostbyname(hostname.c_str());
	if (host == NULL)
	{
		return -1;
	}

	// Construct the address structure for the DNS host
	bcopy((char *)host->h_addr, (char *)&DNSAddress.sin_addr.s_addr, host->h_length);

	printf("%s\n", inet_ntoa(DNSAddress.sin_addr));

	return 1;
}

// Construct a response packet to a recieved request
void buildResponsePacket(DNS_HEADER* dns, char* buffer)
{
	// -- HEADER SECTION -- //
	dns->qr = 1; // query response
	dns->ra = 1; // recursive available
	dns->ans_count = htons(1); // number of answers
	dns->add_count = htons(0); // number of additional responses
	char* bufferStart = buffer; // begins keeping track of buffer size
	// -------------------- //
	
	// -- GETS THE NAME LENGTH OF THE QUERY -- //
	int labelLength;
	char *nameIndex = buffer + sizeof(DNS_HEADER);
	memset(queryName, 0, 256);
	while (labelLength = *nameIndex++)
	{
		while (labelLength--)
		{
            memset(tmp, 0, 256);
			sprintf(tmp, "%c", *nameIndex++);
			strcat(queryName, tmp);
		}
		strcat(queryName, ".");
	}
	strcat(queryName, "\0");
	// ------------------------------------- // 

	// -- QUESTION SECTION -- //
	// get length of name of query
	struct QUESTION* questionInfo = NULL;
	questionInfo = (struct QUESTION*)&buffer[sizeof(struct DNS_HEADER) + (strlen((const char*)queryName) + 1)];
	std::string nameServerWithDot = nameServer + ".";
	if (0 != strcmp(queryName, nameServerWithDot.c_str()))
	{
		printf("Requested name not permitted.\n");
		dns->rcode = 3;
		return;
	}

	// Get the type and class values
	unsigned int qtype = (unsigned int)ntohs(questionInfo->qtype); // decode2bytes(buffer);
	unsigned int qclass = (unsigned int) ntohs(questionInfo->qclass); // decode2bytes(buffer);
	// ---------------------- //

	buffer += HDR_OFFSET; // Set Buffer head pointer to be after the Header
	unsigned int namePtrIndex =HDR_OFFSET; // Grab the index to be used for compression

	buffer += (strlen((const char*)queryName) + 1);  // Set Buffer head pointer to be after the query name
	
	buffer += sizeof(struct QUESTION); // Set Buffer head pointer to be after the qtype and qclass parameters
	
	// -- ANSWER SECTION -- //
	selectIPAddressForClient();

	//encodeCompressedName(buffer, namePtrIndex);
	encodeName(buffer, selectedHostname);

	encode2bytes(buffer, qtype); // set the type
	encode2bytes(buffer, qclass); // set the class
	encode4bytes(buffer, (unsigned long) 0); // set the time to live 

	unsigned int dlength = 4; // HARD SETTING THIS FOR NOW: (4) BYTES FOR LENGTH OF ENCODED IP ADDR
	encode2bytes(buffer, dlength); // Sets the length of the response data

	encodeIPAddr(buffer, selectedIP); // encodes the IP address for the response
	// ------------------ // 

	size = (int)(buffer - bufferStart); // Sets the size of the response packet
}

// encodes a name
void encodeName(char*& buffer, const std::string& domain) {

	int start(0), end; // indexes

	while ((end = domain.find('.', start)) != std::string::npos) {

		*buffer++ = end - start; // label length octet
		for (int i = start; i<end; i++) {

			*buffer++ = domain[i]; // label octets
		}
		start = end + 1; // Skip '.'
	}

	*buffer++ = domain.size() - start; // last label length octet
	for (int i = start; i<domain.size(); i++) {

		*buffer++ = domain[i]; // last label octets
	}

	*buffer++ = 0;
}

// encodes a query parameter
void encode2bytes(char*& buffer, unsigned int value) {

	buffer[0] = (value & 0xFF00) >> 8;
	buffer[1] = value & 0xFF;
	buffer += 2;
}

// encode compressed name
void encodeCompressedName(char*& buffer, unsigned int value)
{
	unsigned int offset = HDR_OFFSET;
	unsigned int pointerMask = 192;
	buffer[0] = (pointerMask & 0xFF);
	buffer[1] = (value & 0xFF);
	buffer += 2; 
}

// encodes a 32 bit parameter
void encode4bytes(char*& buffer, unsigned long value) {

	buffer[0] = (value & 0xFF000000) >> 24;
	buffer[1] = (value & 0xFF0000) >> 16;
	buffer[2] = (value & 0xFF00) >> 16;
	buffer[3] = (value & 0xFF) >> 16;
	buffer += 4;
}

// Encodes the IP addr
void encodeIPAddr(char*& buffer, std::string ipaddr)
{
	char *str = (char*)ipaddr.c_str(), *str2;
	unsigned char value[4] = { 0 };
	size_t index = 0;

	str2 = str; /* save the pointer */
	while (*str) {
		if (isdigit((unsigned char)*str)) {
			value[index] *= 10;
			value[index] += *str - '0';
		}
		else {
			index++;
		}
		str++;
	}
	buffer[0] = value[0];
	buffer[1] = value[1];
	buffer[2] = value[2];
	buffer[3] = value[3];
	buffer += 4;
}

// Resolve all IP's given from the replica server list
void resolveAllReplicaIPs()
{
    openGeoipRequestSocket();
	resolveReplicaIP("ec2-54-210-1-206.compute-1.amazonaws.com");
	resolveReplicaIP("ec2-54-67-25-76.us-west-1.compute.amazonaws.com");
	resolveReplicaIP("ec2-35-161-203-105.us-west-2.compute.amazonaws.com");
	resolveReplicaIP("ec2-52-213-13-179.eu-west-1.compute.amazonaws.com");
	resolveReplicaIP("ec2-52-196-161-198.ap-northeast-1.compute.amazonaws.com");
	resolveReplicaIP("ec2-54-255-148-115.ap-southeast-1.compute.amazonaws.com");
	resolveReplicaIP("ec2-13-54-30-86.ap-southeast-2.compute.amazonaws.com");
	resolveReplicaIP("ec2-52-67-177-90.sa-east-1.compute.amazonaws.com");
	resolveReplicaIP("ec2-35-156-54-135.eu-central-1.compute.amazonaws.com");
    close(geoipSocket);
}

// Resolve and store a ec2 replica server as hostname/IP address pair
void resolveReplicaIP(std::string ec2ReplicaHostname)
{
	struct sockaddr_in hostAddr;
	struct hostent* host; 
	host = gethostbyname(ec2ReplicaHostname.c_str());

	if (host == NULL)
	{
		printf("Unable to resolve hostname: %s. Exiting.\n", ec2ReplicaHostname.c_str());
	}

	bcopy((char *)host->h_addr, (char *)&hostAddr.sin_addr.s_addr, host->h_length);

	std::string IPaddr = inet_ntoa(hostAddr.sin_addr);
    
    std::string replicaLocationData = requestGeoipDataForHost(IPaddr);
    latitudeMap.insert(std::pair<std::string, float>(ec2ReplicaHostname, (float)atof(grabString(replicaLocationData, "\"latitude\":", ",").c_str())));
    longitudeMap.insert(std::pair<std::string, float>(ec2ReplicaHostname, (float)atof(grabString(replicaLocationData, "\"longitude\":", ",").c_str())));

	//addressMap[ec2ReplicaHostname] = IPaddr;
	addressMap.insert(std::pair<std::string, std::string>(ec2ReplicaHostname, IPaddr));
}

// Select which IP to send back to the requester
void selectIPAddressForClient()
{
    selectedHostname = "ec2-54-210-1-206.compute-1.amazonaws.com";
    float selectedDistance = haversineDistance(clientLatitude, clientLongitude, latitudeMap["ec2-54-210-1-206.compute-1.amazonaws.com"], longitudeMap["ec2-54-210-1-206.compute-1.amazonaws.com"]);
    typedef std::map<std::string, std::string>::iterator it_type;
    for(it_type iterator = addressMap.begin(); iterator != addressMap.end(); iterator++)
    {
        float potentialDisance = haversineDistance(clientLatitude, clientLongitude, latitudeMap[iterator->first], longitudeMap[iterator->first]);
        if (potentialDisance < selectedDistance)
        {
            printf("Just promoted %s\nLatitde=%f\nLongitude=%f\n", iterator->first.c_str(), latitudeMap[iterator->first], longitudeMap[iterator->first]);
            printf("Promoted because %f < %f\n", potentialDisance, selectedDistance);
            selectedHostname = iterator->first;
            selectedDistance = potentialDisance;
        }
        else
        {
            printf("No promotion for %s because %f > %f\n", iterator->first.c_str(), potentialDisance, selectedDistance);
        }
    }
    printf("As the best replica, the DNS has chosen %s\n", selectedHostname.c_str());
	selectedIP = addressMap[selectedHostname];
}

// open a socket to freegeoip.net
int openGeoipRequestSocket()
{
    geoipSocket = -1;
    // Attempt to open socket
    geoipSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (geoipSocket < 0)
    {
        printf("Error: socket failed to open. Exiting.\n");
        close(geoipSocket);
        return -1;
    }
    host = gethostbyname("freegeoip.net");
    if (host == NULL)
    {
        // If the host cannot be found, exit the program.
        printf("Error: host not found. Exiting.\n");
        close(geoipSocket);
        return -1;
    }
    // Construct the address structure to bind
    memset(&geoipAddr, 0, sizeof(geoipAddr));
    geoipAddr.sin_port = htons(80);
    geoipAddr.sin_family = AF_INET;
    bcopy((char *)host->h_addr, (char *)&geoipAddr.sin_addr.s_addr, host->h_length);
    
    int connectionResult = connect(geoipSocket, (const sockaddr *)&geoipAddr, sizeof(geoipAddr));
    if (connectionResult < 0)
    {
        printf("Error: failed to establish connection\n");
        close(geoipSocket);
        printf("%d\n", errno);
        return -1;
    }
    return geoipSocket;
}

// ping the freegeoip.net api for geoip data
std::string requestGeoipDataForHost(std::string ipAddr)
{
    memset(geoipRequest, 0, 512);
    sprintf(geoipRequest, "GET /json/%s HTTP/1.0\r\nHost: freegeoip.net\r\nConnection: keep-alive\r\n\r\n", ipAddr.c_str());
    int sendResult = write(geoipSocket, geoipRequest, strlen(geoipRequest));
    if (sendResult < 0)
    {
        printf("Failed to send GET request. Need to alert requester.\n");
        exit(1);
    }
    
    // Receive geoip data from freegeoip.net
    memset(geoipGETresult, 0, 1000);
    int receiveResult = read(geoipSocket, geoipGETresult, 1000);
    if (receiveResult < 0)
    {
        printf("Failed to receive response from GET request. Need to alert requester.\n");
        exit(1);
    }
    std::string result(geoipGETresult);
    return result;
}

// Given a prefix and a suffix, find the first occurence of a string between those
// two values within the given block of html.
std::string grabString(std::string source, std::string beginning, std::string end)
{
    std::size_t beginningLoc = source.find(beginning);
    if (beginningLoc == std::string::npos)
    {
        return "";
    }
    beginningLoc += beginning.length();
    std::string::size_type endLoc = source.find(end, beginningLoc);
    return source.substr(beginningLoc, endLoc - beginningLoc);
}

// converts degrees to radians (for use in the haversine formula)
float degreesToRadians(float degrees)
{
    return ((degrees * pi) / 180);
}

// calculates the distance between two latitude/longitude coordinates via the
// haversine formula
float haversineDistance(float latitude1degrees, float longitude1degrees, float latitude2degrees, float longitude2degrees)
{
    float latitude1radians, longitude1radians, latitude2radians, longitude2radians, u, v;
    latitude1radians = degreesToRadians(latitude1degrees);
    longitude1radians = degreesToRadians(longitude1degrees);
    latitude2radians = degreesToRadians(latitude2degrees);
    longitude2radians = degreesToRadians(longitude2degrees);
    u = sin((latitude2radians - latitude1radians) / 2);
    v = sin((longitude2radians - longitude1radians) / 2);
    return 2.0 * earthRadiusKm * asin(sqrt(u * u + cos(latitude1radians) * cos(latitude2radians) * v * v));
}
