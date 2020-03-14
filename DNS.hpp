#if !defined(MDNS_DNS)

#define MDNS_DNS

#include "defs.hpp" // should come before any inet headers etc

#include <map>
#include <string>
#include <vector>

namespace mDNS
{

namespace DNS
{

//
// See e.g. https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
//
struct Defs
{
	// Message header flag bitmasks; e.g. RFC1035:4.1.1
	static constexpr uint16_t QRMask = 1 << 15;  // 0b1000000000000000
	static constexpr uint16_t OpMask = 15 << 11; // 0b0111100000000000
	static constexpr uint16_t AAMask = 1 << 10;  // 0b0000010000000000
	static constexpr uint16_t TCMask = 1 << 9;   // 0b0000001000000000
	static constexpr uint16_t RDMask = 1 << 8;   // 0b0000000100000000
	static constexpr uint16_t RAMask = 1 << 7;   // 0b0000000010000000
	static constexpr uint16_t ZrMask = 1 << 6;   // 0b0000000001000000
	static constexpr uint16_t ADMask = 1 << 5;   // 0b0000000000100000
	static constexpr uint16_t CDMask = 1 << 4;   // 0b0000000000010000
	static constexpr uint16_t RcMask = 15;       // 0b0000000000001111

	// OpCodes, no obsolete/removed/unassigned; RFC6895
	static constexpr uint16_t QUERY  = 0;
	static constexpr uint16_t STATUS = 2;
	static constexpr uint16_t NOTIFY = 4;
	static constexpr uint16_t UPDATE = 5;
	static constexpr uint16_t DSO    = 6;

	// Return codes, no unassigned/reserved; RFC1035:4.1.1, ignores 6895:2.3
	static constexpr uint16_t NOERROR   = 0;
	static constexpr uint16_t FORMERR   = 1;
	static constexpr uint16_t SERVFAIL  = 2;
	static constexpr uint16_t NXDOMAIN  = 3;
	static constexpr uint16_t NOTIMP    = 4;
	static constexpr uint16_t REFUSED   = 5;
	static constexpr uint16_t YXDOMAIN  = 6;
	static constexpr uint16_t YXRRSET   = 7;
	static constexpr uint16_t NXRRSET   = 8;
	static constexpr uint16_t NOTAUTH   = 9;
	static constexpr uint16_t NOTZONE   = 10;
	static constexpr uint16_t DSOTYPENI = 11;
	static constexpr uint16_t BADVERS   = 16;
	static constexpr uint16_t BADKEY    = 17;
	static constexpr uint16_t BADTIME   = 18;
	static constexpr uint16_t BADMODE   = 19;
	static constexpr uint16_t BADNAME   = 20;
	static constexpr uint16_t BADALG    = 21;
	static constexpr uint16_t BADTRUNC  = 22;
	static constexpr uint16_t BADCOOKIE = 23;

	// RR types, no obsolete/experimental; RFC1035:3.2.2, 3596:2.1, 2782:1.1
	static constexpr uint16_t A = 1;
	static constexpr uint16_t NS    = 2;
	static constexpr uint16_t CNAME = 5;
	static constexpr uint16_t SOA   = 6;
	static constexpr uint16_t NUL   = 10;
	static constexpr uint16_t WKS   = 11;
	static constexpr uint16_t PTR   = 12;
	static constexpr uint16_t HINFO = 13;
	static constexpr uint16_t MINFO = 14;
	static constexpr uint16_t MX    = 15;
	static constexpr uint16_t TXT   = 16;
	static constexpr uint16_t AAAA  = 28;
	static constexpr uint16_t SRV   = 33;
	static constexpr uint16_t ANY   = 255;

	// Classes, "no obsolete" ;) RFC1035:3.2.4
	static constexpr uint16_t IN = 1;

	#define _(txt) {txt, #txt}
		inline static const NameMap<uint16_t> HeaderFlags = {
			_(QRMask),
			_(OpMask),
			_(AAMask),
			_(TCMask),
			_(RDMask),
			_(RAMask),
			_(ZrMask),
			_(ADMask),
			_(CDMask),
			_(RcMask),
		};
		inline static const NameMap<uint16_t> OpCodes = {
			_(QUERY ),
			_(STATUS),
			_(NOTIFY),
			_(UPDATE),
			_(DSO   ),
		};
		inline static const NameMap<uint16_t> ReturnCodes = {
			_(NOERROR  ),
			_(FORMERR  ),
			_(SERVFAIL ),
			_(NXDOMAIN ),
			_(NOTIMP   ),
			_(REFUSED  ),
			_(YXDOMAIN ),
			_(YXRRSET  ),
			_(NXRRSET  ),
			_(NOTAUTH  ),
			_(NOTZONE  ),
			_(DSOTYPENI),
			_(BADVERS  ),
			_(BADKEY   ),
			_(BADTIME  ),
			_(BADMODE  ),
			_(BADNAME  ),
			_(BADALG   ),
			_(BADTRUNC ),
			_(BADCOOKIE),
		};
		inline static const NameMap<uint16_t> RRTypes = {
			_(A    ),
			_(NS   ),
			_(CNAME),
			_(SOA  ),
			_(NUL  ),
			_(WKS  ),
			_(PTR  ),
			_(HINFO),
			_(MINFO),
			_(MX   ),
			_(TXT  ),
			_(AAAA ),
			_(SRV  ),
			_(ANY  ),
		};
		inline static const NameMap<uint16_t> Classes = {
			_(IN),
		};
	#undef _

	template<typename T>
	static const char* get(const NameMap<T>& m, T key)
	{
		const auto it = m.find(key);
		return (it == m.end()) ? nullptr : it->second.c_str();			
	}

	static const char* HeaderFlag(uint16_t k) { return get(HeaderFlags,k); }
	static const char* ReturnCode(uint16_t k) { return get(ReturnCodes,k); }
	static const char* OpCode(uint16_t k) { return get(OpCodes,k); }
	static const char* RRType(uint16_t k) { return get(RRTypes,k); }
	static const char* Class(uint16_t k) { return get(Classes,k); }
};

//
// Parse utilities - deserialization from network buffer
//
struct Parse
{
	// Endian conversion for arbitrary integral data type
	template <typename T>
	static T ntoh(const T& t)
	{
		static const uint16_t one = 1;
		static const bool do_swap = (((const char *)&one)[0] == 1);
		
		if (!do_swap) return t;

		constexpr size_t N = sizeof(T);
		T t_;

		for (size_t i=0; i<N; i++) {
			((char *)&t_)[N-(1+i)] = ((char *)&t)[i];
		}

		return t_;
	}


	template<typename T>
	static size_t atom(const char *bytes, size_t i, size_t max_i, T& t, bool endian = true)
	{
		if (!bytes) {
			WARN("Null bytes pointer!");
			return 0;
		}

		if (i>=max_i) {
			WARN("Attempt to read past buffer (%d,%d)", (int)i, (int)max_i);
			return 0;
		}

		if (!bytes || (i>=max_i)) return 0;

		t = *((T*) &bytes[i]);
		if (endian) t = ntoh(t);
		return i+sizeof(T);
	}

	// Parse byte sequence of [N][b1,b2,...bN] into labels; RFC1035:4.1.4
	// allow_compression: can we follow "pointers" for compression.
	// require_terminator: do we require a final zero-string for clean exit
	static size_t labels(
		const char* bytes,
		size_t i, size_t max_i,
		bool allow_compression,
		bool require_terminator,
		std::vector<std::string>& results)
	{
		uint8_t ptr_bits = 0xc0;    // 0b11000000
		uint16_t idx_bits = 0x3FFF; // 0b0011111111111111
		
		if (!bytes) {
			WARN("Null bytes pointer!");
			return 0;
		}

		while (true) {

			if (i >= max_i) {
				WARN("Attempt to read past buffer (%d,%d)", (int)i, (int)max_i);
				return 0;
			}

			uint8_t compression = bytes[i] & ptr_bits;

			if (compression && !allow_compression) {
				WARN("Label compression where none allowed!");
				return 0;
			}

			// Uncompressed labels
			if (compression == 0) {
				uint8_t lbl_len;

				i = atom(bytes, i, max_i, lbl_len);
				if (lbl_len == 0) return i;

				if (i+lbl_len > max_i) {
					WARN("Label length exceeds buffer: %d+%d, %d", (int)i, (int)lbl_len, (int)max_i);
					return 0;
				}

				results.push_back( std::string(&bytes[i],lbl_len) );
				i += lbl_len;

				// Final zero-length entry not required for e.g. TXT records
				// RFC6763: https://tools.ietf.org/html/rfc6763#section-6.6
				if (!require_terminator && (i==max_i)) {
					return i;
				}
			}
			// Conventional compression in labels
			else if (compression == ptr_bits) {
				uint16_t new_i;

				// Get new offset into packet data
				auto old_i = i;
				i = atom(bytes, i, max_i, new_i);
				new_i = new_i & idx_bits;

				// Check for infinite loop
				if (new_i == old_i) {
					WARN("Infinite loop detected in record - stopping");
					return 0;
				}

				// Check for out-of-bounds jump?
				if (new_i >= max_i) {
					WARN("Out-of-bounds jump: %d->%d, %d", (int)old_i, (int)new_i, (int)max_i);
					return 0;					
				}

 				// Note - return value of parse_labels() ignored, we instead return existing i
				Parse::labels(bytes, new_i, max_i, allow_compression, require_terminator, results);
				return i;
			}
			// Labels are compressed in a manner we do not support.
			else {
				WARN("Compression format (%d) not supported.", compression);
				return 0;
			}
		}
	}
};

//
// DNS message resource record entry - just a lightweight wrapper around the source buffer.
//
struct ResourceRecord
{
	// Header; present in all DNS message sections

	std::string name;
	uint16_t type = 0;
	uint16_t clss = 0;

	// Body; present in answer, authority, and additional sections

	uint32_t TTL = 0;
	uint16_t rd_ofs = 0; // offset into original buffer for payload (in bytes)
	uint16_t rd_len = 0; // length of payload (in bytes)

	// Header and body deserialization invoked explicitly!

	size_t read_header(const char* bytes, size_t i, size_t max_i, std::vector<std::string>& tmp)
	{
		if (!bytes) {
			WARN("Null bytes pointer!");
			return 0;
		}

		// Name: allow compression, require terminal zero-string
		tmp.clear();
		i = Parse::labels(bytes, i, max_i, true, true, tmp);
		if (i==0) {
			return 0;
		}
		
		name = "";
		for (size_t ti=0, N=tmp.size(); ti<N; ti++ ) {
			name += tmp[ti] + ".";
		}

		i = Parse::atom(bytes, i, max_i, type);
		if (i==0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, clss);
		if (i==0) {
			return 0;
		}

		return i;
	}

	size_t read_header_and_body(const char* bytes, size_t i, size_t max_i, std::vector<std::string>& tmp)
	{
		i = read_header(bytes, i, max_i, tmp);
		if (i == 0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, TTL);
		if (i==0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, rd_len);
		if (i==0) {
			return 0;
		}

		rd_ofs = i;
		i += rd_len;

		// Dangerous information!
		if (rd_ofs+rd_len > max_i) {
			WARN("data offset + length exceeds buffer: %d+%d, %d", (int)rd_ofs, (int)rd_len, (int)max_i);
			return 0;
		}

		return i;
	}
};

//
// DNS message - just a lightweight wrapper around the source buffer.
//
struct Message
{
	// Message header ...

	uint16_t id = 0;
	uint16_t flags = 0;

	uint16_t n_question = 0;
	uint16_t n_answer = 0;
	uint16_t n_authority = 0;
	uint16_t n_additional = 0;

	// ... then message body resource records follow in source buffer.

	size_t read_header(const char* bytes, size_t i, size_t max_i)
	{
		if (!bytes) {
			WARN("Null bytes pointer!");
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, id);
		if (i==0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, flags);
		if (i==0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, n_question);
		if (i==0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, n_answer);
		if (i==0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, n_authority);
		if (i==0) {
			return 0;
		}

		i = Parse::atom(bytes, i, max_i, n_additional);
		if (i==0) {
			return 0;
		}

		return i;
	}
};

}

}

#endif
