#if !defined(MDNS_SOCKUTIL)

#define MDNS_SOCKUTIL

#include "defs.hpp" // should come before any inet headers etc

#include <sys/socket.h>
#include <arpa/inet.h>

#include <map>
#include <string>

// Extracting MAC address from packet/link is platform dependent.

#if __APPLE__
	#include <net/if_dl.h> // sockaddr_dl, LLADDR()
	#define LLADDR_(sa) LLADDR((struct sockaddr_dl*)sa)
#elif __linux__
	#include <linux/if_packet.h> // sockaddr_ll
	#define LLADDR_(sa) (((struct sockaddr_ll*)sa)->sll_addr)
#endif


namespace mDNS
{

//
// Socket utility code
//
struct SockUtil
{
	// Socket address types for IP
	using ss  = struct sockaddr_storage;
	using sa4 = struct sockaddr_in;
	using sa6 = struct sockaddr_in6;

	// IP address types
	using ia4 = struct in_addr;
	using ia6 = struct in6_addr;

	#define _(txt) {txt, #txt}
		inline static const NameMap<int> family_map = {
			_(AF_INET),
			_(AF_INET6),
			_(AF_UNIX),
			_(AF_PACKET),
			_(AF_UNSPEC),
		};
	#undef _

	// Non IP4/6 or nullptr returns false.
	template <typename T> static bool is_inet(T *s_)
	{
		auto s = (ss *)s_;

		if (!s) return false;
		return (s->ss_family == AF_INET) || (s->ss_family == AF_INET6);
	}

	// Extract IPv4/6 address from general sockaddr; nullptr check handled by is_inet()
	template <typename T> static sa4* addr4(T* s) { return is_inet(s) ? (sa4 *)s : nullptr; }
	template <typename T> static sa6* addr6(T* s) { return is_inet(s) ? (sa6 *)s : nullptr; }

	// Extract IPv4/6 address from general sockaddr; nullptr check handled by is_inet()
	template <typename T> static ia4* inet4(T* s) { return is_inet(s) ? &addr4(s)->sin_addr : nullptr; }
	template <typename T> static ia6* inet6(T* s) { return is_inet(s) ? &addr6(s)->sin6_addr : nullptr; }

	// Fill sockaddr structure for IPv4/IPv6
	template <typename T> static bool fill4(T* s, const char *ip, int port)
	{
		if (s == nullptr) return false;

		auto family = AF_INET;
		auto a4 = (sa4 *)s; // s->family not yet set, so addr4(s) would return nullptr

		a4->sin_family = family;
		a4->sin_port = htons(port);
		auto result = inet_pton(family, ip, &a4->sin_addr.s_addr);

		return (result == 1) ? true : false;
	}
	template <typename T> static bool fill6(T* s, const char *ip, int port)
	{
		if (s == nullptr) return false;

		auto family = AF_INET6;
		auto a6 = (sa6 *)s; // s->family not yet set, so addr6(s) would return nullptr

		a6->sin6_family = family;
		a6->sin6_port = htons(port);
		auto result = inet_pton(family, ip, &a6->sin6_addr);

		return (result == 1) ? true : false;
	}

	// Extract IPv4/IPv6 family string from general sockaddr
	template <typename T> static const char* af_str(T *s)
	{
		if (!s) return nullptr;
		const auto it = family_map.find( ((ss *)s)->ss_family);
		return (it==family_map.end()) ? ("UNKNOWN") : (it->second.c_str());
	}

	// MAC address (AF_PACKET family type)
	template <typename T> static const char* mac_str(T* s, char *buf, size_t len)
	{
		const auto fmt = "%02x:%02x:%02x:%02x:%02x:%02x";

		if (!s || ((ss *)s)->ss_family != AF_PACKET) return nullptr;
		if (!buf || len<18) {
			WARN("Bad buffer; %p, len %d\n", buf, (int)len);
			return nullptr;
		}

		const auto x = (unsigned char *)LLADDR_(s);
		sprintf(buf, fmt, x[0], x[1], x[2], x[3], x[4], x[5]);
		return buf;
	}

	// Extract IPv4/IPv6 address string from general sockaddr
	template <typename T> static const char* ip_str(T* s, char *buf, size_t len)
	{
		if (!is_inet(s)) return nullptr;

		switch ( ((ss *)s)->ss_family ) {
			case AF_INET:  return inet_ntop(AF_INET,  inet4(s), buf, len); break;
			case AF_INET6: return inet_ntop(AF_INET6, inet6(s), buf, len); break;
		}

		return nullptr;
	}

	// debug
	template <typename T> static void print(T* s)
	{
		char buf[INET6_ADDRSTRLEN];
		auto len = sizeof(buf);

		if (!s) {
			printf("[nullptr sockaddr in SockUtil::print()!]\n");
			return;
		}

		if (!is_inet(s)) {
			printf("[family=%s (%d)]\n", af_str(s), ((ss *)s)->ss_family);
		}
		else {
			if (((ss *)s)->ss_family == AF_INET ) {
				auto a4 = addr4(s);
				if (!a4) {
					ERROR("Unable to extract IPv4 socket address from input pointer!");
				}
				auto port = ntohs(a4->sin_port);
				printf("[family=%s ip=%s port=%d]\n", af_str(s), ip_str(s,buf,len), port);
			}
			else {
				auto a6 = addr6(s);
				if (!a6) {
					ERROR("Unable to extract IPv6 socket address from input pointer!");
				}
				auto port = ntohs(a6->sin6_port);
				printf("[family=%s ip=%s port=%d]\n", af_str(s), ip_str(s,buf,len), port);
			}

		}
	}
};

}

#undef LLADDR_

#endif
