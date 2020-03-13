#include "mDNS.hpp" // include before anything else!

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

namespace {
	volatile std::sig_atomic_t gSignalStatus = 0;
	std::mutex print_mutex;

	void signal_handler(int signal)
	{
		gSignalStatus = signal;
	}
}

void print_dns_rr(const DNS::ResourceRecord& rr, const char* buf, bool is_question)
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

void read_messages(int sd, int timeout_ms, volatile std::sig_atomic_t& status)
{
	DNS::Message msg;
	DNS::ResourceRecord rr;

	// Timeout
	fd_set fds;
	struct timeval timeout;

	// Used in receiving data
	struct sockaddr_storage src, dst;
	int ifc_idx;

	// Incoming packet data goes in here.
	std::vector<char> msg_buf_vec(66000);
	char * const msg_buf = &msg_buf_vec[0];
	const auto msg_buf_max = msg_buf_vec.size();

	// Used in parsing/output.
	char b[INET6_ADDRSTRLEN];
	std::vector<std::string> tmp;

	while (status == 0)
	{
		// Avoid system blocking in DatagramSocket::Read(): only proceed onto actual
		// read where data available on socket.

		if (timeout_ms>0) {
			FD_ZERO(&fds);
			FD_SET(sd, &fds);
			timeout.tv_sec = timeout_ms / 1000;
			timeout.tv_usec = (timeout_ms % 1000) * 1000;
			auto r = select(FD_SETSIZE, &fds, nullptr, nullptr, &timeout);
			if (r < 1) continue;
		}

		auto N = DatagramSocket::Read(sd, msg_buf, msg_buf_max, &src, &dst, &ifc_idx);
		if (N<0) {
			WARN("Listener::Read() returned %d", N);
			continue;
		}


		// Print some packet information

		{
			std::lock_guard<std::mutex> lock(print_mutex);

			printf("\n***********************\n");
			printf("Read %d bytes\n", (int)N);
			printf("%s => ", SockUtil::ip_str(&src, b, sizeof(b)));
			printf("%s : ", SockUtil::ip_str(&dst, b, sizeof(b)));
			printf("delivered_on=%d\n", ifc_idx);

			// Get DNS header information

			size_t i = msg.read_header(msg_buf, 0, N);
			if (i == 0) {
				continue;
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
				i = rr.read_header(msg_buf, i, N, tmp);
				if (i == 0) {
					printf("Problem parsing record.\n");
					break;
				}
				print_dns_rr(rr, msg_buf, true);
			}
			if (i == 0) {
				printf("Problem parsing section.\n");
				continue;
			}

			const char* sections[] = {
				"Answers", "Authority", "Additional"
			};

			int counts[] = {
				msg.n_answer, msg.n_authority, msg.n_additional
			};

			for (int sec_i=0; sec_i<3; sec_i++) {
				printf("%s:\n", sections[sec_i]);
				for (auto rr_i=0; rr_i<counts[sec_i]; rr_i++) {
					i = rr.read_header_and_body(msg_buf, i, N, tmp);
					if (i==0) {
						printf("Problem parsing record.\n");
						break;
					}

					print_dns_rr(rr, msg_buf, false);
				}
				if (i == 0) {
					printf("Problem parsing section.\n");
					break;
				}
			}

			printf("\n");
		}
	}	
}

int main(int argc, char **argv)
{
	using Listener = DatagramSocket;

	Interfaces ifcs;

	int timeout_ms = 100;
	std::vector<ifaddrs *> ifaddrs4, ifaddrs6;

	// Avoid warnings appearing out-of-order relative to normal output

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
		// This is not recognised.
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

		// Allow signal to interrupt system routines like recvmsg
		//if (siginterrupt(signal_type,1) != 0 ) ERROR("siginterrupt()");			

		// Install new handler
		if (sigaction(signal_type, &new_action, nullptr) != 0) {
			ERROR("sigaction()");
		}
	}

	// IPv4 mDNS listener thread

	std::thread thread4( [&ifaddrs4,timeout_ms] {
		auto port = 5353;
		auto IP = "224.0.0.251";

		if (ifaddrs4.size()<1) return;

		int sd = Listener::CreateAndBind(AF_INET, port);
		if (sd < 0) {
			ERROR("Creation/bind failed (%s : %d).\n", IP, port);
		}

		for (const auto& ifa : ifaddrs4) {
			Listener::JoinMulticastGroup(sd, IP, ifa);			
		}
//		Listener::JoinMulticastGroup(sd, IP);

		read_messages(sd, timeout_ms, gSignalStatus);

		printf("thread4 loop ended.\n");

		close(sd);
	});

	// IPv6 mDNS listener thread

	std::thread thread6( [&ifaddrs6,timeout_ms] {
		auto port = 5353;
		auto IP = "ff02::fb";

		if (ifaddrs6.size()<1) return;

		int sd = Listener::CreateAndBind(AF_INET6, port);
		if (sd < 0) {
			ERROR("Creation/bind failed (%s : %d).\n", IP, port);
		}

		for (const auto& ifa : ifaddrs6) {
			Listener::JoinMulticastGroup(sd, IP, ifa);			
		}
//		Listener::JoinMulticastGroup(sd, IP);

		read_messages(sd, timeout_ms, gSignalStatus);

		printf("thread6 loop ended.\n");

		close(sd);
	});

	// Just wait for threads to exit.

	thread4.join();
	printf("Joined thread4\n");

	thread6.join();
	printf("Joined thread6\n");

	printf("done\n");

}
