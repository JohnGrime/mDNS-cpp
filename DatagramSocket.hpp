#if !defined(MDNS_DATAGRAMSOCKET)

#define MDNS_DATAGRAMSOCKET

#include "defs.hpp" // should come before any inet headers etc

#include <net/if.h>  // if_nametoindex()

#include "SockUtil.hpp"

namespace mDNS
{

//
// General procedure: bind a socket to the desired port number using addr_any
// so the socket will (in principle) receive ANY packets tagged with that port
// from ALL interfaces. We then inform the kernel/NIC that we're interested in
// receiving multicast packets on that socket by specifying a multicast IP
// address, and a local interface on which to deliver those packets (the latter
// is specified by providing an IP address assigned to that local interface).
//
// Without joining multicast groups, kernel/NIC will only pass us messages that
// are explictly addressed to one of our interfaces; we must therefore indicate
// that we are interested in the (reserved!) multicast addresses AS WELL as any
// addresses assigned to our own interface(s).
//
struct DatagramSocket
{
	// Datagram metadata: source and destination addresses, index of interface
	// on which the datagram was received (also temp. buffer for collection).
	struct Meta {
		char tmp[1024]; // temporary buffer for metadata
		sockaddr_storage src, dst;
		int ifc_idx;
	};

	static const char * check_(int family)
	{
		if (family == AF_INET) return "AF_INET";
		if (family == AF_INET6) return "AF_INET6";
		ERROR("Unsupported family (%d)", family);
		return nullptr; // stop compiler warning
	}

	// Attempt to create a socket bound to the specified port on all available
	// interfaces (ifc_addr == null) or only the specified interface (via
	// ifc_addr != null). You almost certainly want ifa == null!
	static int CreateAndBind(int family, int port, const struct sockaddr* ifc_addr = nullptr)
	{
		const int on = 1;

		// Check target family is valid

		auto fstr = check_(family);

		// If ifa specified, check ifa->family matches the target family

		if (ifc_addr && (ifc_addr->sa_family!=family)) {
			ERROR("Family mismatch: %s (%d) vs %s (%d)\n",
				fstr, family, SockUtil::af_str(ifc_addr), ifc_addr->sa_family);
		}

		// Create socket with appropriate options set to ensure that whatever
		// port/address the socket binds to can be reused quickly.

		// AF_INET actually has same value as PF_INET etc, but just for correctness.
		int sock_family = (family == AF_INET) ? PF_INET : PF_INET6;

		int s = socket(sock_family, SOCK_DGRAM, 0);
		if (s < 0) ERROR("socket(%s)", fstr);

		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))<0) {
			ERROR("setsockopt(%s,SO_REUSEADDR)", fstr);
		}

		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on))<0) {
			ERROR("setsockopt(%s, SO_REUSEPORT)", fstr);
		}

		// Enable additional info on the socket, such as source and destination
		// addresses; latter useful to e.g. determine which interface received
		// the data if socket bound to ALL interfaces (INADDR_ANY/in6addr_any).

		int proto = (family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
		int option = (family == AF_INET6) ? IPV6_RECVPKTINFO : IP_PKTINFO;

		if (setsockopt(s, proto, option, &on, sizeof(on)) < 0) {
			ERROR("setsockopt(%s,PKTINFO)", fstr);
		}

		// Setup bind information

		struct sockaddr_storage ss;
		size_t bind_len = 0;

		memset(&ss, 0, sizeof(ss));

		switch (family) {
			case AF_INET:
			{
				auto s = (struct sockaddr_in *) &ss;
				bind_len = sizeof(*s); // deref for correct size!

				s->sin_family = family;
				s->sin_port = htons(port);
				s->sin_addr.s_addr = htonl(INADDR_ANY); // htonl(); INADDR_ANY maybe != 0

				if (ifc_addr) {
					auto addr = SockUtil::inet4(ifc_addr);
					if (!addr) ERROR("Bad IPv4 address");
					s->sin_addr.s_addr = htonl(addr->s_addr);
				}
			}
			break;

			case AF_INET6:
			{
				auto s = (struct sockaddr_in6 *) &ss;
				bind_len = sizeof(*s); // deref for correct size!

				s->sin6_family = family;
				s->sin6_port = htons(port);
				s->sin6_addr = in6addr_any; // no htonl(); IPv6 constants endian-agnostic

				if (ifc_addr) {
					auto addr = SockUtil::inet6(ifc_addr);
					if (!addr) ERROR("Bad IPv6 address");
					s->sin6_addr = *addr;
				}
			}
			break;
		}

		// Bind socket

		if (bind(s, (struct sockaddr *)&ss, bind_len) != 0) {
			ERROR("bind(%s,%d)", fstr, port);
		}

		return s;
	}

	// Allow precisely specified local recipient address via ifaddrs parameter;
	// same IP can be assigned to different interfaces on different networks
	// (e.g. lan & wifi both assigned 10.x.y.z or 192.168.x.y where their local
	// networks are not bridged), and same interface can have multiple IPs.
	// This means an interface number or IP address alone may not uniquely
	// specify a specific address/interface on which to receive multicast
	// packets. An ifaddrs structure is *not* ambiguous!
	//
	// If ifa == nullptr, join on any/default interface(s).
	//
	// Note: if another process has already joined the multicast group on this
	// interface (Bonjour, Avahi etc), we may already be receiving multicasts
	// without needing to call this - but call it in case we're the first!
	static void JoinMulticastGroup(int sd, const char *mcast_ip, const ifaddrs *ifa = nullptr)
	{
		struct sockaddr sa;
		socklen_t len = sizeof(sa);

		// Determine appropriate domain, check suitability; only need family, so
		// doesn't matter if rest of data truncated in getsockname()

		if (getsockname(sd, &sa, &len) != 0) {
			ERROR("getsockname() failed");
		}

		int domain = sa.sa_family;

		check_(domain);

		// Protocol-specific setup

		switch (domain) {
			case AF_INET:
			{
				struct ip_mreqn g; // prefer newer ip_mreqn structure to ip_mreq

				if (inet_pton(domain, mcast_ip, &g.imr_multiaddr)!=1) {
					ERROR("inet_pton(%s)", mcast_ip);
				}

				// No ifaddrs specified? Receive on any interface/address,
				// otherwise us specified interface.
				if (ifa == nullptr) {
					g.imr_address.s_addr = htonl(INADDR_ANY);
					g.imr_ifindex = 0;
				}
				else {
					g.imr_address = *SockUtil::inet4(ifa->ifa_addr);
					g.imr_ifindex = if_nametoindex(ifa->ifa_name);
				}

				if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &g, sizeof(g)) < 0) {
					ERROR("setsockopt(%s,JOIN_MULTI)", check_(domain));
				}
			}
			break;

			case AF_INET6:
			{
				struct ipv6_mreq g;

				if (inet_pton(domain, mcast_ip, &g.ipv6mr_multiaddr)!=1) {
					ERROR("inet_pton(%s)", mcast_ip);
				}

				// No ifaddrs specified? Use default multicast interface,
				// otherwise use specified interface.
				if (ifa == nullptr) {
					g.ipv6mr_interface = 0; // https://github.com/sccn/liblsl/issues/36
				}
				else {
					g.ipv6mr_interface = if_nametoindex(ifa->ifa_name);
				}

				if (setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &g, sizeof(g)) < 0) {
					ERROR("setsockopt(%s,JOIN_MULTI)", check_(domain));
				}
			}
			break;
		}
	}

	//
	// Read from socket, acquiring information about the data source and local interface/IP.
	// Only family and address regions of metadata dst are valid after call!
	//
	static int Read(int sd, void *buf, size_t len, Meta& meta)
	{
		if (!buf || (len<1)) return -1;

		memset(&meta.src, 0, sizeof(meta.src));
		memset(&meta.dst, 0, sizeof(meta.dst));
		meta.ifc_idx = 0;

		struct iovec iov;
		{
			iov.iov_base = buf;
			iov.iov_len = len;
		}

		struct msghdr mh;
		{
			mh.msg_name = &meta.src;
			mh.msg_namelen = sizeof(meta.src);

			mh.msg_iov = &iov;
			mh.msg_iovlen = 1;

			mh.msg_control = meta.tmp;
			mh.msg_controllen = sizeof(meta.tmp);
		}

		auto result = recvmsg(sd, &mh, 0);
		if (result<0) {
			WARN("recvmsg() returned %d", result);
			return result;
		}

		if (mh.msg_controllen == sizeof(meta.tmp)) {
			WARN("metadata is potentially truncated");
		}

		for (struct cmsghdr* c = CMSG_FIRSTHDR(&mh); c!=NULL; c = CMSG_NXTHDR(&mh,c))
		{
			auto lvl = c->cmsg_level;
			auto typ = c->cmsg_type;

			if ((lvl==IPPROTO_IP) && (typ==IP_PKTINFO)) {
				auto pi = (in_pktinfo *) CMSG_DATA(c);
				auto index = pi->ipi_ifindex;
				auto addr_ptr = &pi->ipi_addr;

				meta.dst.ss_family = AF_INET;
				memcpy(SockUtil::inet4(&meta.dst), addr_ptr, sizeof(*addr_ptr));
				meta.ifc_idx = index;

				break;
			}

			if ((lvl==IPPROTO_IPV6) && (typ==IPV6_PKTINFO)) {
				auto pi = (in6_pktinfo *) CMSG_DATA(c);
				auto index = pi->ipi6_ifindex;
				auto addr_ptr = &pi->ipi6_addr;

				meta.dst.ss_family = AF_INET6;
				memcpy(SockUtil::inet6(&meta.dst), addr_ptr, sizeof(*addr_ptr));
				meta.ifc_idx = index;

				break;
			}
		}

		return result;
	}
};


}

#endif
