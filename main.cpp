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

void print_dns_rr(const DNS::ResourceRecord& rr, const char* buf, bool is_question)
{
	using Defs = DNS::Defs;

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
			DNS::Parse::labels(buf, i, max_i, true, true, tmp);

			for (const auto& str: tmp) printf("%s.", str.c_str());
				printf(" ");
		break;

		case Defs::SRV:
		{
			uint16_t priority, weight, port;

			i = DNS::Parse::atom(buf, i, max_i, priority);
			i = DNS::Parse::atom(buf, i, max_i, weight);
			i = DNS::Parse::atom(buf, i, max_i, port);

			DNS::Parse::labels(buf, i, max_i, true, true, tmp);

			for (const auto& str: tmp) printf("%s.", str.c_str());
			printf(" priority=%d weight=%d port=%d ", priority, weight, port);
		}
		break;

		case Defs::TXT:
			DNS::Parse::labels(buf, i, max_i, true, false, tmp);
			for (const auto& str: tmp) printf("'%s' ", str.c_str());
		break;
	}
	printf( "}\n" );
}

int main(int argc, char **argv)
{
	using Defs = DNS::Defs;
	using Listener = MulticastListener;

	Interfaces ifcs;

	DNS::Message msg;
	DNS::ResourceRecord rr;

	ifaddrs* ifa = nullptr;

	// Incoming packets go in here.
	std::vector<char> msg_buf_vec(66000);
	char * const msg_buf = &msg_buf_vec[0];
	const auto msg_buf_max = msg_buf_vec.size();

	std::vector<std::string> tmp;

	// Print all interfaces
	if (argc<2) {
		for (const auto& ifc : ifcs.interfaces) print_interface_info(ifc);
		exit(0);
	}

	setbuf(stdout, nullptr);
	setbuf(stderr, nullptr);

	// Find specified interface via IP
	{
		auto receive_IP = argv[1];
		auto ifc = ifcs.LookupByIP(receive_IP, &ifa);
		if (!ifc) ERROR("IP '%s' not found.\n", receive_IP);

		printf("'%s' => '%s' %d\n", receive_IP, ifc->name.c_str(), ifc->index);
		printf("Addresses associated with this interface:\n");
		for (const auto ifa : ifc->addresses) SockUtil::print(ifa->ifa_addr);
		printf("\n");
	}

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

	//
	// Launch listener
	//

	int sd;

	// Set up mDNS listener socket

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

	// Process incoming mDNS messages

	while (true)
	{
		struct sockaddr_storage src, dst;
		int index;

		auto N = Listener::Read(sd, msg_buf, msg_buf_max, &src, &dst, &index);
		if (N<0) ERROR("read()");

		// Print some packet information

		{
			char b[64];

			printf("\n***********************\n");
			printf("Read %d bytes\n", (int)N);
			printf("%s => ", SockUtil::ip_str(&src, b, sizeof(b)));
			printf("%s : ", SockUtil::ip_str(&dst, b, sizeof(b)));
			printf("delivered_on=%d\n", index);
		}

		// Save packet

		{
			auto f = fopen("packet.data","w");
			fwrite(msg_buf,N,1,f);
			fclose(f);
		}

		// Get DNS header information

		size_t i = msg.read_header(msg_buf, 0, N);
		if (i == 0) {
			continue;
		}

		// Print header info

		printf("{id %d : flags (%d)", msg.id, msg.flags);
		for (const auto& it : Defs::HeaderFlags) {
			if (msg.flags & it.first) printf(" %s", it.second.c_str());
		}
		printf("}\n");

		// Print resource record sections

		printf("Questions:\n");
		for (auto ii=0; ii<msg.n_question; ii++) {
			i = rr.read_header(msg_buf, i, N, tmp);
			if (i==0) break;

			print_dns_rr(rr, msg_buf, true);
		}
		if (i == 0) {
			printf("Problem parsing section.\n");
			continue;
		}

		printf("Answers:\n");
		for (auto ii=0; ii<msg.n_answer; ii++) {
			i = rr.read_header_and_body(msg_buf, i, N, tmp);
			if (i==0) break;

			print_dns_rr(rr, msg_buf, false);
		}
		if (i == 0) {
			printf("Problem parsing section.\n");
			continue;
		}

		printf("Authority:\n");
		for (auto ii=0; ii<msg.n_authority; ii++) {
			i = rr.read_header_and_body(msg_buf, i, N, tmp);
			if (i==0) break;

			print_dns_rr(rr, msg_buf, false);
		}
		if (i == 0) {
			printf("Problem parsing section.\n");
			continue;
		}

		printf("Additional:\n");
		for (auto ii=0; ii<msg.n_additional; ii++) {
			i = rr.read_header_and_body(msg_buf, i, N, tmp);
			if (i==0) break;

			print_dns_rr(rr, msg_buf, false);
		}
		if (i == 0) {
			printf("Problem parsing section.\n");
			continue;
		}

		printf("\n");
	}

	close(sd);
}
