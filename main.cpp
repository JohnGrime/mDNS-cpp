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

using Callback = std::function<int (mDNS::DNS::ResourceRecord*)>;

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
		std::vector<char> buf_vec(66000);
		char *buf = &buf_vec[0];
		auto len = buf_vec.size();

		DNS::Message msg;
		std::vector<std::string> tmp;
		std::map<uint16_t,Callback> callbacks;

		char IP_buf[64];

		using Listener = mDNS::MulticastListener;

		//
		// Set up listener callbacks
		//

		auto print_rr = [] (DNS::ResourceRecord *rr) -> int {
			printf("-> Parse %s (%d)\n", DNS::Defs::RRType(rr->type), rr->type);
			return 0;
		};

		// Default callbacks
		for (const auto [type, str]: DNS::Defs::RRTypes) callbacks[type] = print_rr;

		// TXT parser
		callbacks[DNS::Defs::TXT] = [buf,&tmp,&print_rr] (DNS::ResourceRecord *rr) -> int {
				size_t i = rr->rd_ofs;
				size_t max_i = i + rr->rd_len;

				bool lbl_compress = true;
				bool lbl_terminate = false;

				print_rr(rr);
				DNS::Util::parse_labels(buf, i, max_i, lbl_compress, lbl_terminate, tmp);
				for (const auto& str: tmp) printf("'%s' ", str.c_str());
				printf("\n");
				return 0;
			};

		// PTR callback
		callbacks[DNS::Defs::PTR] = [buf,&tmp,&print_rr] (DNS::ResourceRecord *rr) -> int {
				size_t i = rr->rd_ofs;
				size_t max_i = i + rr->rd_len;

				bool lbl_compress = true;
				bool lbl_terminate = true;

				print_rr(rr);
				DNS::Util::parse_labels(buf, i, max_i, lbl_compress, lbl_terminate, tmp);
				for (const auto& str: tmp) printf("%s.", str.c_str());
				printf("\n");
				return 0;
			};

		// SRV callback
		callbacks[DNS::Defs::SRV] = [buf,&tmp,&print_rr] (DNS::ResourceRecord *rr) -> int {
				size_t i = rr->rd_ofs;
				size_t max_i = i + rr->rd_len;

				bool lbl_compress = true;
				bool lbl_terminate = true;

				print_rr(rr);
				uint16_t priority, weight, port;
				i = DNS::Util::parse_atom(buf, i, max_i, priority, true);
				i = DNS::Util::parse_atom(buf, i, max_i, weight, true);
				i = DNS::Util::parse_atom(buf, i, max_i, port, true);
				DNS::Util::parse_labels(buf, i, max_i, lbl_compress, lbl_terminate, tmp);
				for (const auto& str: tmp) printf("%s.", str.c_str());
				printf(" : priority=%d : weight=%d : port=%d\n",priority,weight,port);
				return 0;
			};

		// A callback
		callbacks[DNS::Defs::A] = [buf,&print_rr] (DNS::ResourceRecord *rr) -> int {
				print_rr(rr);
				char b[64]; // keep separate from packet buffer!
				printf("%s\n", inet_ntop(AF_INET, &buf[rr->rd_ofs], b, sizeof(b)) );
				return 0;
			};

		// AAAA callback
		callbacks[DNS::Defs::AAAA] = [buf,&print_rr] (DNS::ResourceRecord *rr) -> int {
				print_rr(rr);
				char b[64]; // keep separate from packet buffer!
				printf("%s\n", inet_ntop(AF_INET6, &buf[rr->rd_ofs], b, sizeof(b)) );
				return 0;
			};

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

			for (auto v : {&msg.answer, &msg.authority, &msg.additional} ) {
				for (auto& rr : *v ) {

					const auto it = callbacks.find(rr.type);
					if (it == callbacks.end()) {
						printf("[No callback found for type %d]\n", rr.type);
						continue;
					}

					it->second(&rr);
				}
			}

			msg.print_();
			printf("\n");
		}

		close(sd);
	}
}
