#if !defined(MDNS_SOCKUTIL)

#define MDNS_SOCKUTIL

#include "defs.hpp" // must come before any inet headers!

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_dl.h> //LLADDR()

#include <map>
#include <string>

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

	// Extract IPv4/6 address from general sockaddr
	template <typename T> static ia4* inet4(T *s) { return (is_inet(s)) ? &((sa4 *)s)->sin_addr : nullptr; }
	template <typename T> static ia6* inet6(T *s) { return (is_inet(s)) ? &((sa6 *)s)->sin6_addr : nullptr; }

	// Extract IPv4/IPv6 family string from general sockaddr
	template <typename T> static const char* af_str(T *s)
	{
		if (!s) return nullptr;
		const auto it = family_map.find( ((ss *)s)->ss_family);
		return (it==family_map.end()) ? ("UNKNOWN") : (it->second.c_str());
	}

	// MAC address (AF_PACKET family type)
	template <typename T> static const char* mac_str(T *s, char *buf, size_t len)
	{
		if (!s || ((ss *)s)->ss_family != AF_PACKET) return nullptr;
		if (!buf || len<18) {
			WARN("Bad buffer; %p, len %d\n", buf, (int)len);
			return nullptr;
		}

		const auto fmt = "%02x:%02x:%02x:%02x:%02x:%02x";
		const auto x = (unsigned char *)LLADDR((struct sockaddr_dl *)s);
		sprintf(buf, fmt, x[0], x[1], x[2], x[3], x[4], x[5]);
		return buf;
	}

	// Extract IPv4/IPv6 address string from general sockaddr
	template <typename T> static const char* ip_str(T *s, char *buf, size_t len)
	{
		if (!is_inet(s)) return nullptr;

		switch ( ((ss *)s)->ss_family ) {
			case AF_INET:  return inet_ntop(AF_INET,  inet4(s), buf, len); break;
			case AF_INET6: return inet_ntop(AF_INET6, inet6(s), buf, len); break;
		}

		return nullptr;
	}

	// debug
	template <typename T> static void print(T *s)
	{
		char buf[64];
		auto len = sizeof(buf);

		if (!s) {
			printf("[nullptr sockaddr in SockUtil::print()!]\n");
			return;
		}

		printf("[family=%s ip=%s]\n", af_str(s), ip_str(s,buf,len));
	}
};

}

#endif
