#if !defined(MDNS_INTERFACES)

#define MDNS_INTERFACES

#include "defs.hpp" // should come before any inet headers etc

#include <ifaddrs.h> // getifaddrs(), freeifaddrs()
#include <net/if.h>  // IFF_<x>, if_nametoindex(), if_indextoname()

#include <vector>

#include "SockUtil.hpp"

namespace mDNS
{

struct Interfaces
{
	//
	// We sort the assigned addresses by interface, with interface name and
	// index for convenience. Note that we can always convert between interface
	// name and index using the if_nametoindex() and if_indextoname() functions.
	//
	using Interface = struct {
		std::string name;
		unsigned int index;
		std::vector<struct ifaddrs *> addresses;
	};

	#define _(txt) {txt, #txt}
	inline static const NameMap<uint16_t> iff_flag_map = {
		// Restricted subset only!
		_(IFF_UP),
		_(IFF_BROADCAST),
		_(IFF_LOOPBACK),
		_(IFF_POINTOPOINT),
		_(IFF_RUNNING),
		_(IFF_NOARP),
		_(IFF_PROMISC),
		_(IFF_NOTRAILERS),
		_(IFF_ALLMULTI),
		_(IFF_MULTICAST),
	};
	#undef _

	std::vector<Interface> interfaces;

	// Backing store for address data in interfaces[]
	struct ifaddrs *ifa_ = nullptr;

	static const char * GetName(unsigned int index, char *buf)
	{
		return if_indextoname(index, buf);
	}

	static unsigned int GetIndex(const char *name)
	{
		return if_nametoindex(name);
	}

	static bool IsLoopback(const ifaddrs * ifa)
	{
		if (ifa == nullptr) return false;
		return (ifa->ifa_flags & IFF_LOOPBACK) ? true : false;
	}

	static bool IsMulticast(const ifaddrs * ifa)
	{
		if (ifa == nullptr) return false;
		return (ifa->ifa_flags & IFF_MULTICAST) ? true : false;
	}

	Interfaces()
	{
		Refresh();
	}

	~Interfaces()
	{
		Clear();
	}

	void Refresh()
	{
		using ifc_idx_t = unsigned int;
		std::map<ifc_idx_t, size_t> i2i;

		Clear();

		// Get all addresses assigned to any interface, and add to the
		// appropriate Interface structures in the interfaces[] vector.

		if (getifaddrs(&ifa_) != 0) ERROR("getifaddrs()");

		for (auto x=ifa_; x!=nullptr; x=x->ifa_next) {
			const auto idx = if_nametoindex(x->ifa_name);
			const auto it = i2i.find(idx);
			if (it == i2i.end()) {
				i2i[idx] = interfaces.size();
				interfaces.push_back( {x->ifa_name,idx,{x}} );
			}
			else {
				interfaces[it->second].addresses.push_back(x);
			}
		}
	}

	void Clear()
	{
		if (ifa_) freeifaddrs(ifa_);
		interfaces.clear();
	}

	//
	// Slow methods - cache results where possible
	//
	
	const Interface* LookupByName(const char *name)
	{
		if (!name) return nullptr;

		for (const auto& x : interfaces) {
			if (strcmp(x.name.c_str(),name) == 0) return &x;
		}

		return nullptr;
	}

	const Interface* LookupByIP(const char *IP, ifaddrs **ifa_ = nullptr)
	{
		char buf[INET6_ADDRSTRLEN];
		auto len = sizeof(buf);

		if (!IP) return nullptr;

		for (const auto& interface : interfaces) {
			for (const auto& ifa : interface.addresses) {
				auto sa = ifa->ifa_addr;
				if (!SockUtil::is_inet(sa)) continue;
				if (!SockUtil::unpack(sa,buf,len)) ERROR("str(%s)\n", IP);
				if (strcmp(IP,buf) == 0) {
					if (ifa_ != nullptr) *ifa_ = ifa;
					return &interface;
				}
			}
		}

		return nullptr;
	}

	// Debug.
	static void print_(const Interface& ifc)
	{
		char buf[INET6_ADDRSTRLEN];
		auto len = sizeof(buf);

		printf("%s [%d]\n", ifc.name.c_str(), ifc.index);

		for (const auto ifa : ifc.addresses) {

			printf("  %s (%d)\n", SockUtil::af_str(ifa->ifa_addr), ifa->ifa_addr->sa_family);

			printf("    ifa_flags: ");
			for (auto &x : Interfaces::iff_flag_map) {
				if (ifa->ifa_flags & x.first) printf("%s ", x.second.c_str());
			}
			printf("\n");

			if (SockUtil::is_inet(ifa->ifa_addr)) {
				printf("    ifa_addr: %s\n", SockUtil::unpack(ifa->ifa_addr,buf,len));
				printf("    ifa_netmask: %s\n", SockUtil::unpack(ifa->ifa_netmask,buf,len));
				printf("    ifa_broadaddr: %s\n", SockUtil::unpack(ifa->ifa_broadaddr,buf,len));
			}
			else if (ifa->ifa_addr->sa_family == AF_PACKET) {
				printf("    MAC: %s\n", SockUtil::mac_str(ifa->ifa_addr,buf,len));
			}

			printf("\n");
		}		
	}	
};

}

#endif
