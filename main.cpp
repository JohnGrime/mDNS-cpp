#include "mDNS.hpp" // should come before any inet headers etc

#include <unistd.h>

#include <atomic>
#include <csignal>
#include <mutex>
#include <thread>

using namespace mDNS;

//
// Handy links:
//
// https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
// https://tools.ietf.org/html/rfc3542
// https://docs.oracle.com/cd/E19455-01/806-1017/6jab5di2e/index.html
//

// Anonymous namespace with various local junk.

namespace {

// Simple wrapper for select() on set of file descriptors with a timeout.

struct TimeoutSelect
{
	fd_set fds;
	struct timeval tv;

	int Select(int timeout_ms, std::initializer_list<int> const& descriptors)
	{
		FD_ZERO(&fds);
		for (auto d: descriptors) { FD_SET(d, &fds); }
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;
		return select(FD_SETSIZE, &fds, nullptr, nullptr, &tv);
	}
};

// Thread control variables

volatile std::sig_atomic_t gSignalStatus = 0;

// Catch SIGINT etc

void signal_handler(int signal)
{
	gSignalStatus = signal;
}

// Debug print routines

void print_dns_rr(const DNS::ResourceRecord& rr,const char* msg_buf, bool is_question)
{
	using Defs = DNS::Defs;

	char b[INET6_ADDRSTRLEN];
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
			printf("%s ", inet_ntop(AF_INET, &msg_buf[i], b, sizeof(b)) );
		break;

		case Defs::AAAA:
			printf("%s ", inet_ntop(AF_INET6, &msg_buf[i], b, sizeof(b)) );
		break;

		case Defs::PTR:
			DNS::Parse::labels(msg_buf, i, max_i, true, true, tmp);

			for (const auto& str: tmp) printf("%s.", str.c_str());
				printf(" ");
		break;

		case Defs::SRV:
		{
			uint16_t priority, weight, port;

			i = DNS::Parse::atom(msg_buf, i, max_i, priority);
			i = DNS::Parse::atom(msg_buf, i, max_i, weight);
			i = DNS::Parse::atom(msg_buf, i, max_i, port);

			DNS::Parse::labels(msg_buf, i, max_i, true, true, tmp);

			for (const auto& str: tmp) printf("%s.", str.c_str());
			printf(" priority=%d weight=%d port=%d ", priority, weight, port);
		}
		break;

		case Defs::TXT:
			DNS::Parse::labels(msg_buf, i, max_i, true, false, tmp);
			for (const auto& str: tmp) printf("'%s' ", str.c_str());
		break;
	}
	printf( "}\n" );
}

void print_dns_msg(
	const char *msg_buf, int msg_buflen,
	DatagramSocket::Meta* meta = nullptr)
{
	DNS::Message msg;
	DNS::ResourceRecord rr;

	char b[INET6_ADDRSTRLEN];
	std::vector<std::string> tmp;

	printf("\n***********************\n");
	printf("Read %d bytes\n", (int)msg_buflen);
	if (meta) {
		printf("%s => ", SockUtil::ip_str(&meta->src, b, sizeof(b)));
		printf("%s : ", SockUtil::ip_str(&meta->dst, b, sizeof(b)));
		printf("delivered_on=%d\n", meta->ifc_idx);
	}

	// Get DNS header information

	size_t i = msg.read_header(msg_buf, 0, msg_buflen);
	if (i == 0) {
		return;
	}

	// Print header info

	printf("{id %d : flags (%d)", msg.id, msg.flags);
	for (const auto& it : DNS::Defs::HeaderFlags) {
		if (msg.flags & it.first) printf(" %s", it.second.c_str());
	}
	printf("}\n");

	// Print resource record sections

	printf("Questions:\n");

	for (auto rr_i=0; rr_i<msg.n_question; rr_i++) {
		i = rr.read_header(msg_buf, i, msg_buflen, tmp);
		if (i == 0) {
			printf("Problem parsing record.\n");
			return;
		}
		print_dns_rr(rr, msg_buf, true);
	}

	const char* sections[] = { "Answers", "Authority", "Additional" };
	int counts[] = { msg.n_answer, msg.n_authority, msg.n_additional };

	for (int sec_i=0; sec_i<3; sec_i++) {
		printf("%s:\n", sections[sec_i]);
		for (auto rr_i=0; rr_i<counts[sec_i]; rr_i++) {
			i = rr.read_header_and_body(msg_buf, i, msg_buflen, tmp);
			if (i==0) {
				printf("Problem parsing record.\n");
				return;
			}
			print_dns_rr(rr, msg_buf, false);
		}
	}

	printf("\n");	
}

}

// IPv4/6 threads call this to collect and print messages

void read_messages(
	int family, int port, const char *IP,
	const std::vector<ifaddrs *>* ifa_vec,
	int timeout_ms,
	volatile std::sig_atomic_t& status,
	std::mutex* print_mutex = nullptr)
{
	TimeoutSelect ts;
	DatagramSocket::Meta meta;

	std::vector<char> msg_buf(66000);

	if (!IP) return;
	if (ifa_vec && ifa_vec->size()<1) return;

	int sd = DatagramSocket::CreateAndBind(family, port);
	if (sd < 0) {
		ERROR("Creation/bind failed (%s : %d).\n", IP, port);
	}

	// See note in DatagramSocket::JoinMulticastInterface()
	if (ifa_vec) {
		for (const auto& ifa : *ifa_vec) {
			DatagramSocket::JoinMulticastGroup(sd, IP, ifa);
		}
	}
	else {
		DatagramSocket::JoinMulticastGroup(sd, IP);
	}

	while (status == 0) {
		// Don't block - only proceed to Read() when data available
		if ((timeout_ms>0) && (ts.Select(timeout_ms,{sd})<1) ) continue;

		auto N = DatagramSocket::Read(sd, &msg_buf[0], msg_buf.size(), meta);
		if (N<0) {
			WARN("DatagramSocket::Read() returned %d", N);
			continue;
		}

		// Avoids intermingled output
		if (print_mutex) {
			std::lock_guard<std::mutex> lock(*print_mutex);
			print_dns_msg(&msg_buf[0], N, &meta);
		}
		else {
			print_dns_msg(&msg_buf[0], N, &meta);
		}
	}

	close(sd);
}

int main(int argc, char **argv)
{
	Interfaces ifcs;

	int timeout_ms = 100;
	std::vector<ifaddrs *> ifaddrs4, ifaddrs6;

	std::mutex print_mutex;

	// Avoid warnings/errors appearing out-of-order relative to normal output

	setbuf(stdout, nullptr);
	setbuf(stderr, nullptr);

	// If no arguments, print all interfaces

	if (argc<2) {
		for (const auto& ifc : ifcs.interfaces) Interfaces::print_(ifc);
		exit(0);
	}

	// Args may be interface names or IP addresses; test in that order.

	for (int i=1; i<argc; i++ )
	{
		ifaddrs* ifa = nullptr;

		// Is this a valid interface name?
		if (auto ifc = ifcs.LookupByName(argv[i])) {
			printf("'%s' => interface (%d)\n", argv[i], ifc->index);
			for (const auto ifa : ifc->addresses) {
				auto sa = ifa->ifa_addr;

				if (!SockUtil::is_inet(sa)) {
					continue;
				}

				if (sa->sa_family == AF_INET) {
					ifaddrs4.push_back(ifa);
				}
				else {
					ifaddrs6.push_back(ifa);
				} 
			}
		}
		// Is this a valid IP address?
		else if (auto ifc = ifcs.LookupByIP(argv[i], &ifa)) {
			auto sa = ifa->ifa_addr;

			if (sa->sa_family == AF_INET) {
				printf("'%s' => IPv4 on %s (%d).\n", argv[i], ifc->name.c_str(), ifc->index);
				ifaddrs4.push_back(ifa);
			}
			else {
				printf("'%s' => IPv6 on %s (%d).\n", argv[i], ifc->name.c_str(), ifc->index);
				ifaddrs6.push_back(ifa);
			}
		}
		// This is not a recognised interface name or local IP address.
		else
		{
			printf("'%s' is not an interface name or assigned address.\n", argv[i]);
		}
	}

	if ((ifaddrs4.size()==0) && (ifaddrs6.size()==0)) {
		ERROR("No valid interfaces or addresses specified.\n");
	}

	// Signal handler; signal() deprecated, use sigaction() if possible.

	{
		const auto signal_type = SIGINT;
		struct sigaction new_action;

		if (sigemptyset(&new_action.sa_mask) != 0) {
			ERROR("sigemptyset()");
		}
		
		new_action.sa_handler = signal_handler;
		new_action.sa_flags = 0;

		// Allow signal to interrupt system routines like recvmsg; we avoid
		// needing this by using select with a timeout while reading messages.
		//if (siginterrupt(signal_type,1) != 0 ) ERROR("siginterrupt()");			

		// Install new handler
		if (sigaction(signal_type, &new_action, nullptr) != 0) {
			ERROR("sigaction()");
		}
	}

	// IPv4 mDNS listener thread

	std::thread thread4( [&ifaddrs4,timeout_ms,&print_mutex] {
		auto port = 5353;
		auto IP = "224.0.0.251";

		if (ifaddrs4.size()<1) return;
		read_messages(AF_INET, port, IP, &ifaddrs4, timeout_ms, gSignalStatus, &print_mutex);
	});

	// IPv6 mDNS listener thread

	std::thread thread6( [&ifaddrs6,timeout_ms,&print_mutex] {
		auto port = 5353;
		auto IP = "ff02::fb";

		if (ifaddrs6.size()<1) return;
		read_messages(AF_INET6, port, IP, &ifaddrs6, timeout_ms, gSignalStatus, &print_mutex);
	});

	// Just wait for threads to exit.

	thread4.join();
	printf("Joined thread4\n");

	thread6.join();
	printf("Joined thread6\n");

	printf("done\n");

}
