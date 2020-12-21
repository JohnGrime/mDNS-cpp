/*
	Author: John Grime
*/

#if !defined(MDNS_DEFS)

#define MDNS_DEFS

#if __APPLE__
	#define AF_PACKET AF_LINK
	#define __APPLE_USE_RFC_3542 // IPV6_PKTINFO - define BEFORE net headers
#elif __linux__
	// should work without any special considerations
#else
	#error "Only macOS and Linux are supported"
#endif

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <map>
#include <string>

//
// Some fundamental bits and pieces that are uses throughout
//

namespace mDNS
{

// Map something of type T to a string name
template <typename T> using NameMap = std::map<T,std::string>;

// Warning/error logging (possibly to multiple output streams)
struct Log
{
	static void notify_(FILE *f,
		const char *in_file, const char *in_func, int on_line,
		const char *format, va_list args)
	{
		if (!f) return;
		
		fprintf(f, "! %s : line %d : in %s() : ", in_file, on_line, in_func);
		vfprintf(f, format, args);
		if (errno != 0) {
			fprintf(f, " (last errno %d : '%s')", errno, strerror(errno));
		}
		fprintf(f, "\n");
		fflush(f);
	}

	static void Notify(const char *in_file,
		const char *in_function, int on_line,
		bool should_exit,
		const char *format, ...)
	{
		va_list args;

		// Write to stderr ...

		va_start(args, format);
			notify_(stderr, in_file, in_function, on_line, format, args);
		va_end(args);

		// .. and into other files?

		if (should_exit) exit(EXIT_FAILURE);
	}
};

}

// Utility macros that insert current file/function/line into Notify() call
#define WARN(...)  { mDNS::Log::Notify( __FILE__, __func__, __LINE__, false, __VA_ARGS__ ); }
#define ERROR(...) { mDNS::Log::Notify( __FILE__, __func__, __LINE__,  true, __VA_ARGS__ ); }

#endif
