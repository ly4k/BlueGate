#include <iostream>
#include <WS2tcpip.h>

#include <openssl/ssl.h>

#define PKT_TYPE_CONNECT_REQ 1
#define PKT_TYPE_CONNECT_RESP 2
#define PKT_TYPE_PAYLOAD 3
#define PKT_TYPE_DISCONNECT 4
#define PKT_TYPE_CONNECT_REQ_FRAGMENT 5

struct DTLSParams {
	SSL_CTX* ctx;
	SSL* ssl;
	BIO* bio;
};

struct UDP_PACKET_HEADER {
	USHORT pktID;
	USHORT pktLen;
};

struct AASYNDATA {
	USHORT uUpStreamMtu;
	USHORT uDownStreamMtu;
	DWORD fLossy;
	DWORD snSendISN;
};

struct AASYNDATARESP {
	USHORT uUpStreamMtu;
	USHORT uDownStreamMtu;
	DWORD snRecvISN;
};

struct CONNECT_PKT {
	UDP_PACKET_HEADER hdr;
	USHORT usPortNumber;
	USHORT cbAuthnCookieLen;
	AASYNDATA SynData;
};

struct CONNECT_PKT_RESP {
	UDP_PACKET_HEADER hdr;
	AASYNDATARESP SynResponse;
	DWORD64 result;
};

struct CONNECT_PKT_FRAGMENT {
	UDP_PACKET_HEADER hdr; // 4 bytes
	USHORT usFragmentID; // 2 bytes
	USHORT usNoOfFragments; // 2 bytes
	USHORT cbFragmentLength; // 2 bytes
	BYTE fragment[1000];  // 250 bytes
};