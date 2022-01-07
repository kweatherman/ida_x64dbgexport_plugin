
// IDA plugin utility support
#include "StdAfx.h"
#include <tchar.h>
#include <winnt.h>

qstring &GetVersionString(UINT32 version, qstring &version_string)
{
	version_string.sprnt("%u.%u.%u", GET_VERSION_MAJOR(MY_VERSION), GET_VERSION_MINOR(MY_VERSION), GET_VERSION_PATCH(MY_VERSION));
	VERSION_STAGE stage = GET_VERSION_STAGE(version);
	switch (GET_VERSION_STAGE(version))
	{
		case VERSION_ALPHA:	version_string += "-alpha";	break;
		case VERSION_BETA: version_string += "-beta"; break;
	};
	return version_string;
}

LPCSTR TimestampString(TIMESTAMP time, __out_bcount_z(64) LPSTR buffer)
{
	if(time >= HOUR)
		sprintf_s(buffer, 64, "%.2f hours", (time / (TIMESTAMP) HOUR));
	else
	if(time >= MINUTE)
		sprintf_s(buffer, 64, "%.2f minutes", (time / (TIMESTAMP) MINUTE));
	else
	if(time < (TIMESTAMP) 0.01)
		sprintf_s(buffer, 64, "%.2f ms", (time * (TIMESTAMP) 1000.0));
	else
		sprintf_s(buffer, 64, "%.2f seconds", time);
	return buffer;
}

LPSTR NumberCommaString(UINT64 n, __out_bcount_z(32) LPSTR buffer)
{
	int i = 0, c = 0;
	do
	{
		buffer[i] = ('0' + (n % 10)); i++;

		n /= 10;
		if ((c += (3 && n)) >= 3)
		{
			buffer[i] = ','; i++;
			c = 0;
		}

	} while (n);
	buffer[i] = 0;
	return _strrev(buffer);
}

// ------------------------------------------------------------------------------------------------

// Print C exception information
int ReportException(LPCSTR name, LPEXCEPTION_POINTERS nfo)
{
	msg(MSG_TAG "** Exception: 0x%08X @ 0x%llX, in %s()! **\n", nfo->ExceptionRecord->ExceptionCode, nfo->ExceptionRecord->ExceptionAddress, name);
	return EXCEPTION_EXECUTE_HANDLER;
}
