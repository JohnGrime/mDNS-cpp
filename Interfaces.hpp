#if !defined(MDNS_INTERFACES)

#define MDNS_INTERFACES

#include "defs.hpp" // must come before any inet headers!

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
	// Slow methods - avoid where possible!
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
		char buf[64];
		auto len = sizeof(buf);

		if (!IP) return nullptr;

		for (const auto& interface : interfaces) {
			for (const auto& ifa : interface.addresses) {
				auto sa = ifa->ifa_addr;
				if (!SockUtil::is_inet(sa)) continue;
				if (!SockUtil::ip_str(sa,buf,len)) ERROR("str(%s)\n", IP);
				if (strcmp(IP,buf) == 0) {
					if (ifa_ != nullptr) *ifa_ = ifa;
					return &interface;
				}
			}
		}

		return nullptr;
	}
};

}

#endif
