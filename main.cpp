#include "mDNS.hpp" // include before anything else!

#include <unistd.h>

using namespace mDNS;

//
// Handy links:
//
// https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
// https://tools.ietf.org/html/rfc3542
// https://docs.oracle.com/cd/E19455-01/806-1017/6jab5di2e/index.html
//

void print_interface_info(const Interfaces::Interface& ifc)
{
	char buf[64];
	auto len = sizeof(buf);

	printf("%s [%d]\n", ifc.name.c_str(), ifc.index);

	for (const auto ifa : ifc.addresses) {

		printf("  %s\n", SockUtil::af_str(ifa->ifa_addr));

		printf("    ifa_flags: ");
		for (auto &x : Interfaces::iff_flag_map) {
			if (ifa->ifa_flags & x.first) printf("%s ", x.second.c_str());
		}
		printf("\n");

		if (SockUtil::is_inet(ifa->ifa_addr)) {
			printf("    ifa_addr: %s\n", SockUtil::ip_str(ifa->ifa_addr,buf,len));
			printf("    ifa_netmask: %s\n", SockUtil::ip_str(ifa->ifa_netmask,buf,len));
			printf("    ifa_broadaddr: %s\n", SockUtil::ip_str(ifa->ifa_broadaddr,buf,len));
		}
		else if (ifa->ifa_addr->sa_family == AF_PACKET) {
			printf("    MAC: %s\n", SockUtil::mac_str(ifa->ifa_addr,buf,len));
		}

		printf("\n");
	}		
}

void print_dns_rr(const mDNS::DNS::ResourceRecord& rr, const char* buf, bool is_question)
{
	using Defs = mDNS::DNS::Defs;

	char b[64];
	std::vector<std::string> tmp;

	printf("  {name=%s, type=%s (%d), class=%s (%d)} {TTL=%d rd_len=%d}",
		rr.name.c_str(),
		Defs::RRType(rr.type), rr.type,
		Defs::Class(rr.clss), rr.clss,
		rr.TTL, rr.rd_len );

	if (is_question) {
		printf("\n");
		return;
	}

	size_t i = rr.rd_ofs;
	size_t max_i = i + rr.rd_len;

	tmp.clear();

	printf( " { " );
	switch (rr.type) {
		case Defs::A:
			printf("%s ", inet_ntop(AF_INET, &buf[i], b, sizeof(b)) );
		break;

		case Defs::AAAA:
			printf("%s ", inet_ntop(AF_INET6, &buf[i], b, sizeof(b)) );
		break;

		case Defs::PTR:
			DNS::Util::parse_labels(buf, i, max_i, true, true, tmp);

			for (const auto& str: tmp) printf("%s.", str.c_str());
				printf(" ");
		break;

		case Defs::SRV:
		{
			uint16_t priority, weight, port;

			i = DNS::Util::parse_atom(buf, i, max_i, priority, true);
			i = DNS::Util::parse_atom(buf, i, max_i, weight, true);
			i = DNS::Util::parse_atom(buf, i, max_i, port, true);

			DNS::Util::parse_labels(buf, i, max_i, true, true, tmp);

			for (const auto& str: tmp) printf("%s.", str.c_str());
			printf(" priority=%d weight=%d port=%d ", priority, weight, port);
		}
		break;

		case Defs::TXT:
			DNS::Util::parse_labels(buf, i, max_i, true, false, tmp);
			for (const auto& str: tmp) printf("'%s' ", str.c_str());
		break;
	}
	printf( "}\n" );
}

int main(int argc, char **argv)
{
	Interfaces ifcs;
	ifaddrs* ifa = nullptr;

	std::string str;

	// Print all interfaces
	if (argc<2) {
		for (const auto& ifc : ifcs.interfaces) print_interface_info(ifc);
		exit(0);
	}

	setbuf(stdout, nullptr);
	setbuf(stderr, nullptr);

	auto receive_IP = argv[1];
	auto ifc = ifcs.LookupByIP(receive_IP, &ifa);
	if (!ifc) ERROR("IP '%s' not found.\n", receive_IP);

	printf("'%s' => '%s' %d\n", receive_IP, ifc->name.c_str(), ifc->index);
	printf("Addresses associated with this interface:\n");
	for (const auto ifa : ifc->addresses) SockUtil::print(ifa->ifa_addr);
	printf("\n");

	/*
	// Print selected interfaces
	if (false)
	{
		std::vector<const char *> v = {"en0","en1","nope"};

		for (const auto x : v) {
			auto ifc = ifcs.LookupByName(x);
			if (!ifc) {
				printf("interface '%s' not found.\n", x);
				continue;
			}
			print_interface(*ifc);
		}
	}
	*/

	printf("here we go ... \n");

	{
		using Defs = mDNS::DNS::Defs;

		std::vector<char> buf_vec(66000);
		char *buf = &buf_vec[0];
		auto len = buf_vec.size();

		DNS::Message msg;
		std::vector<std::string> tmp;

		char IP_buf[64];

		using Listener = mDNS::MulticastListener;

		//
		// Launch listener
		//

		int sd;

		{
			auto sa = ifa->ifa_addr;
			auto port = 5353;
			auto IP = (sa->sa_family == AF_INET) ? "224.0.0.251" : "ff02::fb";

			sd = Listener::CreateAndBind(sa->sa_family, port);
			if (sd < 0) {
				ERROR("Creation/bind failed (%s : %d).\n", IP, port);
			}

			Listener::JoinMulticastGroup(sd, IP, ifa);
		}

		while (true)
		{
			struct sockaddr_storage src, dst;
			int index;

			auto N = Listener::Read(sd, buf, len, &src, &dst, &index);
			if (N<0) ERROR("read()");

			printf("\n***********************\n");
			printf("Read %d bytes\n", (int)N);
			printf("%s => ", SockUtil::ip_str(&src, IP_buf, sizeof(IP_buf)));
			printf("%s : ", SockUtil::ip_str(&dst, IP_buf, sizeof(IP_buf)));
			printf("delivered_on=%d\n", index);

			{
				auto f = fopen("packet.data","w");
				fwrite(buf,N,1,f);
				fclose(f);
			}

			msg.deserialize(buf, 0, N, tmp);

			// Print header

			printf("{id %d : flags (%d)", msg.id, msg.flags);
			for (const auto& it : Defs::HeaderFlags) {
				if (msg.flags & it.first) printf(" %s", it.second.c_str());
			}
			printf("}\n");

			// Print sections

			for (auto v : {&msg.question, &msg.answer, &msg.authority, &msg.additional} ) {
				for (auto& rr : *v) {
					print_dns_rr(rr, buf, (v == &msg.question));
				}
			}

			printf("\n");
		}

		close(sd);
	}
}
