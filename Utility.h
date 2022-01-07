
// IDA plugin utility support
#pragma once

// ------------------------------------------------------------------------------------------------

// Size of string with out terminator
#define SIZESTR(x) (_countof(x) - 1)

#define ALIGN(_x_) __declspec(align(_x_))

#define STACKALIGN(type, name) \
	BYTE space_##name[sizeof(type) + (16-1)]; \
	type &name = *reinterpret_cast<type *>((UINT_PTR) (space_##name + (16-1)) & ~(16-1))

// Now you can use the #pragma message to add the location of the message:
// Examples:
// #pragma message(__LOC__ "important part to be changed")
// #pragma message(__LOC2__ "error C9901: wish that error would exist")
#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define __LOC__ __FILE__ "("__STR1__(__LINE__)") : Warning MSG: "
#define __LOC2__ __FILE__ "("__STR1__(__LINE__)") : "

// ------------------------------------------------------------------------------------------------

// Semantic versioning for storage 32bit UINT32, using 10 bits (for 0 to 1023) for major, minor, and patch numbers
// Then 2 bits to (for up to 4 states) to indicate alpha, beta, etc.
enum VERSION_STAGE
{
	VERSION_RELEASE,
	VERSION_ALPHA,
	VERSION_BETA
};
#define MAKE_SEMANTIC_VERSION(_stage, _major, _minor, _patch) ((((UINT32)(_stage) & 3) << 30) | (((UINT32)(_major) & 0x3FF) << 20) | (((UINT32)(_minor) & 0x3FF) << 10) | ((UINT32)(_patch) & 0x3FF))
#define GET_VERSION_STAGE(_version) ((VERSION_STAGE)(((UINT32) (_version)) >> 30))
#define GET_VERSION_MAJOR(_version) ((((UINT32) (_version)) >> 20) & 0x3FF)
#define GET_VERSION_MINOR(_version) ((((UINT32) (_version)) >> 10) & 0x3FF)
#define GET_VERSION_PATCH(_version) (((UINT32) (_version)) & 0x3FF)

qstring &GetVersionString(UINT32 version, qstring &version_string);

// ------------------------------------------------------------------------------------------------

typedef double TIMESTAMP;
#define SECOND 1
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)

__inline TIMESTAMP GetTimestamp() { return((TIMESTAMP) GetTickCount64() / (TIMESTAMP) 1000.0); }

// ------------------------------------------------------------------------------------------------

LPCSTR TimestampString(TIMESTAMP time, __out_bcount_z(64) LPSTR buffer);
LPSTR NumberCommaString(UINT64 n, __out_bcount_z(32) LPSTR buffer);

// IDA qstring trim leading and trailing spaces in place
__inline qstring &trim(qstring &s)
{
	auto start = s.begin();
	auto end = s.end();
	auto org_start = start;
	auto org_end = end-1;

	while ((start != end) && std::isspace(*start)) { start++; };
	do { end--; } while ((std::distance(start, end) > 0) && std::isspace(*end));

	if ((start != org_start) || (end != org_end))
		s = qstring(start, (end - start));
	return s;
}

// ------------------------------------------------------------------------------------------------

int ReportException(LPCSTR name, LPEXCEPTION_POINTERS nfo);
#define EXCEPT() __except(ReportException(__FUNCTION__, GetExceptionInformation())){}
#define CATCH() catch (...) { msg(MSG_TAG "** Exception in %s()! ***\n", __FUNCTION__); }

