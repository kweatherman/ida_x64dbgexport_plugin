
// IDA Pro x64dbg data exporter plugin
#include "StdAfx.h"
#include <set>
#include <vector>
#include <memory>
#include "WaitBoxEx.h"

LPCSTR MENU_PATH = "Edit/x64dbg Exporter/";

// To skip spacer type comments
#define COMMENT_MIN_SIZE 3

#define LEVEL1_INDENT "\t"
#define LEVEL2_INDENT LEVEL1_INDENT LEVEL1_INDENT
#define LEVEL3_INDENT LEVEL1_INDENT LEVEL1_INDENT LEVEL1_INDENT
#define json_puts(_str) do{ fputs((_str), fp); }while(0);
#define json_format(_format,...) do{ fprintf_s(fp, (_format), __VA_ARGS__); }while(0);

// From x64dbg SDK "TitanEngine.h"
#define UE_HARDWARE_EXECUTE 4
#define UE_HARDWARE_WRITE 5
#define UE_HARDWARE_READWRITE 6
#define UE_HARDWARE_SIZE_1 7
#define UE_HARDWARE_SIZE_2 8
#define UE_HARDWARE_SIZE_4 9
#define UE_HARDWARE_SIZE_8 10
const UINT32 BP_SOFTWARE = 0;
const UINT32 BP_HARDWARE = 1;

// Do x64dbg export action
// Export options
const WORD OPT_BRANCH	   = 0b0001; // Code branch labels
const WORD OPT_DATA		   = 0b0010; // Data segment labels
const WORD OPT_COMMENTS	   = 0b0100; // Code and data comments
const WORD OPT_BREAKPOINTS = 0b1000; // IDA breakpoint list

enum DEMANGLE_OPTION: int
{
	DMO_None,
	DMO_Demangle
};

// Address string container
struct STRING_ENTRY
{
	qstring name;
	UINT64 address;
};
typedef std::vector<STRING_ENTRY> STRING_LIST;

// Forward defs
void ShowExportStats(WORD exportOptions);
void DoExport(FILE *fp, WORD exportOptions, DEMANGLE_OPTION demangleOption);
void ProcessCodeSegment(const segment_t &seg, WORD exportOptions, __out STRING_LIST &labelList, __out STRING_LIST &commentList);
void ProcessDataSegment(const segment_t &seg, WORD exportOptions, __out STRING_LIST &labelList, __out STRING_LIST &commentList);
void ExportBreakpoints(FILE *fp, LPCSTR moduleEntry);
BOOL isUserFunctionName(LPCSTR name);
BOOL isUserBranchLabel(__in LPCSTR label);
qstring &ProcessLabel(__inout qstring &str, DEMANGLE_OPTION demangleOption);
qstring &JsonEscapeEncode(__inout qstring &str);
BOOL checkBreak();

TIMESTAMP startExportTime = 0;
UINT64 idbBaseEa = 0;
UINT32 functionNames = 0, branchLabels = 0, dataLabels = 0, commentCount = 0, breakpointCount = 0;
UINT32 checkCounter = 0;
BOOL isUserBreak = FALSE;

// For use in inner processing loops.
// Check for WaitBoxEx user abort every nth loop to minimize the update/check overhead.
#define ABORT_UPDATE_CHECK() if (++checkCounter & 2048) { if (checkBreak()) break; }

void DoExport()
{
	// Do options dialog
	WORD exportOptions = (OPT_BRANCH | OPT_DATA | OPT_COMMENTS /*| OPT_BREAKPOINTS*/);
	const char exportDialog[] =
	{
		"BUTTON YES* Next\n" // "Next" instead of the "okay" button

		// Title
		"x64db Export:\n\n"

		// Options. Order must match option bit flags above,
		"<#Export function branch labels in addition to function names.#Include branch labels.:C>\n"
		"<#Export labels from the data sections.#Data lables.:C>\n"
		"<#Export code comments.#Comments.:C>\n"
		"<#Export the IDA breakpoint list.#Breakpoints.:C20>>\n\n"

		// Demangle options dropdown
		"<Demangle names:b:0::>\n"

		"\n"
		"Click \"Next\" to select file..   \n"
		" \n"
	};

	functionNames = branchLabels = dataLabels = commentCount = breakpointCount = 0;
	isUserBreak = FALSE;

	DEMANGLE_OPTION demangleOption = DMO_None;
	qstrvec_t demangleOptions;
	demangleOptions.push_back("Don't demangle");
	demangleOptions.push_back("Demangle (experimental)");

	if (ask_form(exportDialog, &exportOptions, &demangleOptions,&demangleOption) == 1)
	{
		if (exportOptions)
		{
			// Ask for the save file path
			LPSTR fileMask = "*.dd32";
			if (inf_is_64bit())
				fileMask = "*.dd64";
			if (LPSTR userSavePath = ask_file(TRUE, fileMask, "x64dbg Export: Select save file"))
			{
				startExportTime = GetTimestamp();

				// Add a default file extension if none supplied
				char ext[_MAX_EXT] = { 0 };
				if (_splitpath_s(userSavePath, NULL, 0, NULL, 0, NULL, 0, ext, sizeof(ext)) != EINVAL)
				{
					qstring savePath(userSavePath);
					if (!ext[0])
					{
						if (inf_is_64bit())
							savePath += ".dd64";
						else
							savePath += ".dd32";
					}

					// Create json export file
					msg("\n" MSG_TAG "Exporting IDB to : \"%s\"\n", savePath.c_str());
					WaitBox::show("x64dbExport", "Working..");
					WaitBox::updateAndCancelCheck(-1);
					WaitBox::processIdaEvents();

					FILE *fp = NULL;
					if (fopen_s(&fp, savePath.c_str(), "wbS") == 0)
					{
						json_puts("{\n");
							DoExport(fp, exportOptions, demangleOption);
						json_puts("}\n");

						fclose(fp);
						fp = NULL;

						WaitBox::hide();
						if (!checkBreak())
							ShowExportStats(exportOptions);
						WaitBox::processIdaEvents();
					}
				}
			}
		}
	}
}

void ShowExportStats(WORD options)
{
	// Show export stats
	TIMESTAMP exportTime = (GetTimestamp() - startExportTime);
	char buffer[64];
	msg(MSG_TAG "Exported: ");
	msg("%s function names", NumberCommaString(functionNames, buffer));
	if ((options & OPT_BRANCH) && branchLabels)
		msg(", %s branch labels",NumberCommaString(branchLabels, buffer));
	if ((options & OPT_DATA) && dataLabels)
		msg(", %s data labels", NumberCommaString(dataLabels, buffer));
	if ((options & OPT_COMMENTS) && commentCount)
		msg(", %s comments", NumberCommaString(commentCount, buffer));
	if ((options & OPT_BREAKPOINTS) && breakpointCount)
		msg(", %s breakpoints",NumberCommaString(breakpointCount, buffer));
	//msg("\n");
	msg(", in %s.\n", TimestampString(exportTime, buffer));
}

void DoExport(FILE *fp, WORD options, DEMANGLE_OPTION demangle)
{
	char idbBaseName[_MAX_FNAME] = { 0 };
	get_root_filename(idbBaseName, sizeof(idbBaseName));
	_strlwr_s(idbBaseName, sizeof(idbBaseName));
	idbBaseEa = get_imagebase();

	// Build the constant module name entry
	char moduleEntry[_MAX_FNAME + sizeof(LEVEL3_INDENT "'module': ''\n")] = {0};
	sprintf_s(moduleEntry, sizeof(moduleEntry), LEVEL3_INDENT "\"module\": \"%s\",\n", idbBaseName);

	// Start the JSON file with a custom info comment entry
	char dateBuffer[16] = { 0 }, timeBuffer[16] = { 0 };
	char inputFileBuffer[MAX_PATH] = { 0 };
	get_input_file_path(inputFileBuffer, sizeof(inputFileBuffer));
	LPSTR fs = inputFileBuffer;
	while (fs = strchr(fs, '\\')) *fs = '/';
	json_format(LEVEL1_INDENT "\"export_comment\": \"Generated by '" TARGET_NAME "' on %s %s, from IDA DB: '%s'\",\n\n", _strdate(dateBuffer), _strtime(timeBuffer), inputFileBuffer);

	// Iterate segments to gather function names, branch & data labels, and comments
	msg(MSG_TAG "Walking segments:\n");
	WaitBox::processIdaEvents();
	const std::set<qstring> nameBlacklist = { "HEADER", ".tls", ".rsrc", ".idata"};
	STRING_LIST labelList, commentList;

	for (int i = 0; i < get_segm_qty(); i++)
	{
		if (const segment_t *seg = getnseg(i))
		{
			if (seg->size() > 0)
			{
				switch (seg->type)
				{
					case SEG_CODE:
					{
						qstring name;
						if (!get_segm_name(&name, seg))	name = "??";

						// Skip segments that won't normally have labels nor useful comments
						if (nameBlacklist.find(name) == nameBlacklist.end())
						{
							msg(" Code segment \"%s\" %014llX - %014llX\n", name.c_str(), (UINT64) seg->start_ea, (UINT64) seg->end_ea);
							WaitBox::processIdaEvents();
							ProcessCodeSegment(*seg, options, labelList, commentList);
						}
					}
					break;

					case SEG_DATA:
					case SEG_BSS:
					{
						if ((options & OPT_DATA) || (options & OPT_COMMENTS))
						{
							qstring name;
							if (!get_segm_name(&name, seg))	name = "??";

							if (nameBlacklist.find(name) == nameBlacklist.end())
							{
								msg(" Data segment \"%s\" %014llX - %014llX\n", name.c_str(), (UINT64) seg->start_ea, (UINT64) seg->end_ea);
								WaitBox::processIdaEvents();
								ProcessDataSegment(*seg, options, labelList, commentList);
							}
						}
					}
					break;
				};
			}
		}

		if (checkBreak())
			return;
	}

	// Write labels array
	if (!labelList.empty())
	{
		json_puts(LEVEL1_INDENT "\"labels\": [\n");
		for (auto& e : labelList)
		{
			json_puts(LEVEL2_INDENT "{\n");
			json_format(LEVEL3_INDENT "\"text\": \"%s\",\n", ProcessLabel(e.name, demangle).c_str());
			json_puts(LEVEL3_INDENT "\"manual\": false,\n");
			json_puts(moduleEntry);
			json_format(LEVEL3_INDENT "\"address\": \"0x%llX\"\n", e.address);
			json_puts(LEVEL2_INDENT "},\n");

			ABORT_UPDATE_CHECK();
		}
		fseek(fp, -((long)SIZESTR(",\n")), SEEK_END);
		json_puts("\n");
		json_puts(LEVEL1_INDENT "],\n\n");
	}
	else
		json_puts(LEVEL1_INDENT "\"labels\": [],\n\n");

	if (checkBreak())
		return;

	// Write comments array
	if (!commentList.empty())
	{
		commentCount = (UINT32) commentList.size();

		json_puts(LEVEL1_INDENT "\"comments\": [\n");
		for (auto& e : commentList)
		{
			json_puts(LEVEL2_INDENT "{\n");
			json_format(LEVEL3_INDENT "\"text\": \"%s\",\n", JsonEscapeEncode(trim(e.name)).c_str());
			json_puts(LEVEL3_INDENT "\"manual\": false,\n");
			json_puts(moduleEntry);
			json_format(LEVEL3_INDENT "\"address\": \"0x%llX\"\n", e.address);
			json_puts(LEVEL2_INDENT "},\n");

			ABORT_UPDATE_CHECK();
		}
		fseek(fp, -((long)SIZESTR(",\n")), SEEK_END);
		json_puts("\n");
		json_puts(LEVEL1_INDENT "],\n\n");
	}
	else
		json_puts(LEVEL1_INDENT "\"comments\": [],\n\n");

	if (checkBreak())
		return;

	// Write breakpoints array
	if ((options & OPT_BREAKPOINTS) && get_bpt_qty())
	{
		json_puts(LEVEL1_INDENT "\"breakpoints\": [\n");
		ExportBreakpoints(fp, moduleEntry);
		json_puts(LEVEL1_INDENT "]\n");
	}
	else
		json_puts(LEVEL1_INDENT "\"breakpoints\": []\n");
}

// Process code segment to gather function names, branch labels, and comments
void ProcessCodeSegment(const segment_t &seg, WORD options, __out STRING_LIST &labelList, __out STRING_LIST &commentList)
{
	ea_t ptr = seg.start_ea;
	ea_t end = seg.end_ea;

	while (ptr != BADADDR)
	{
		flags_t flags = get_flags_ex(ptr, 0);

		// Function here?
		const func_t *funcPtr = NULL;
		if (is_func(flags))
		{
			// Yes, get it's name
			funcPtr = get_func(ptr);
			qstring name;
			if (get_func_name(&name, ptr) > 0)
			{
				// The IDA name local name flag is not reliable to determine if names are autogenerated or user named.
				// And BinDiff seems messes with the flags too.
				// So using naming patterns to determine if a name is autogenerated or not.

				// Push the name if it's not autogenerated
				if (isUserFunctionName(name.c_str()))
				{
					labelList.push_back({ name, (ptr - idbBaseEa) });
					functionNames++;
				}
			}
	}
		else
		// Otherwise, a user named branch label here?
		if (options & OPT_BRANCH)
		{
			if (has_any_name(flags))
			{
				qstring name;
				if (get_ea_name(&name, ptr) > 0)
				{
					// Push the name if it's not autogenerated
					if (isUserBranchLabel(name.c_str()))
					{
						labelList.push_back({ name, (ptr - idbBaseEa) });
						branchLabels++;
					}
				}
			}
		}

		// Push comment if one exists at this address
		if (options & OPT_COMMENTS)
		{
			// For normal user comments, where one presses the default hotkey ';', the comment will be "repeatable".
			// The non-repeatable types tend to be IDA autogenerated ones.

			// If is a function, look for function comment first
			qstring comment;
			if (funcPtr)
			{
				if ((get_func_cmt(&comment, funcPtr, TRUE) > COMMENT_MIN_SIZE) || (get_func_cmt(&comment, funcPtr, FALSE) > COMMENT_MIN_SIZE))
					commentList.push_back({ comment, (ptr - idbBaseEa) });
			}

			if (comment.size() <= COMMENT_MIN_SIZE)
			{
				// Comment here?
				if (has_cmt(flags))
				{
					if ((get_cmt(&comment, ptr, TRUE) > COMMENT_MIN_SIZE) || (get_cmt(&comment, ptr, FALSE) > COMMENT_MIN_SIZE))
						commentList.push_back({ comment, (ptr - idbBaseEa) });
				}
				else
				// Else look for an anterior or posterior one instead
				// Note: They would both be at the same address (although placed above or below the display line) so probably couldn't display
				// them both in x64bg practicality.
				if (has_extra_cmts(flags))
				{
					if ((get_extra_cmt(&comment, ptr, E_PREV) > COMMENT_MIN_SIZE) || (get_extra_cmt(&comment, ptr, E_NEXT) > COMMENT_MIN_SIZE))
						commentList.push_back({ comment, (ptr - idbBaseEa) });
				}
			}
		}

		ABORT_UPDATE_CHECK();

		// Next defined item..
		ptr = next_head(ptr, end);
	};
}

void ProcessDataSegment(const segment_t &seg, WORD options, __out STRING_LIST &labelList, __out STRING_LIST &commentList)
{
	ea_t ptr = seg.start_ea;
	ea_t end = seg.end_ea;

	while (ptr != BADADDR)
	{
		flags_t flags = get_flags_ex(ptr, 0);

		// This could add a ton of labels like "off_146127018", "qword_146502990", "unk_1465029AB", etc., etc., without filtering for large IDBs.
		// Which adds (optionally) a lot of entries to the DB but then they show up as useful context and as anchors while debugging.
		// Plus these can be used as symbols to jump to in IDA directly.
		if (options & OPT_DATA)
		{
			if (has_any_name(flags))
			{
				qstring label;
				if (get_ea_name(&label, ptr) > 0)
				{
					labelList.push_back({ label, (ptr - idbBaseEa) });
					dataLabels++;
				}
			}
		}

		// TODO: Apparently data comments are not displayed any place in x64dbg.
		// Not seen in the CPU/disassembly, stack, nor dump views.
		#if 0
		// Push comment if one exists at this address
		if (options & OPT_COMMENTS)
		{
			// For normal user comments, where one presses the default hotkey ';', the comment will be "repeatable".
			// The non-repeatable types tend to be IDA autogenerated ones.

			if (has_cmt(flags))
			{
				qstring comment;
				if ((get_cmt(&comment, ptr, TRUE) > COMMENT_MIN_SIZE) || (get_cmt(&comment, ptr, FALSE) > COMMENT_MIN_SIZE))
					commentList.push_back({ comment, (ptr - idbBaseEa) });
			}
			else
			// Else use the anterior or posterior comment if there is one instead
			// They would both be at the same address (although placed above or below the display line) so probably couldn't really
			// Display them both in x64bg(?) with out having a mess probably.
			if (has_extra_cmts(flags))
			{
				qstring comment;
				if ((get_extra_cmt(&comment, ptr, E_PREV) > COMMENT_MIN_SIZE) || (get_extra_cmt(&comment, ptr, E_NEXT) > COMMENT_MIN_SIZE))
					commentList.push_back({ comment, (ptr - idbBaseEa) });
			}
		}
		#endif

		ABORT_UPDATE_CHECK();

		// Next defined item..
		ptr = next_head(ptr, end);
	};
}

// Write breakpoint array entries
// https://hex-rays.com/products/ida/support/idadoc/1076.shtml
void ExportBreakpoints(FILE *fp, LPCSTR moduleEntry)
{
	STACKALIGN(bpt_t, nfo);
	ZeroMemory(&nfo, sizeof(bpt_t));
	nfo.cb = sizeof(bpt_t);

	int count = get_bpt_qty();
	for (int i = 0; i < count; i++)
	{
		if (getn_bpt(i, &nfo))
		{
			UINT64 relAddr = -1, absAddr = -1;
			switch (nfo.loc.type())
			{
				case bpt_loctype_t::BPLT_ABS:
				{
					relAddr = (UINT64) (nfo.ea - idbBaseEa);
					absAddr = nfo.ea;
				}
				break;

				case bpt_loctype_t::BPLT_SYM:
				case bpt_loctype_t::BPLT_REL:
				{
					relAddr = (UINT64) nfo.loc.offset();
					absAddr = (idbBaseEa + relAddr);
				}
				break;

			  // TODO:
				case bpt_loctype_t::BPLT_SRC:
				break;
			};

			if (relAddr != -1)
			{
				UINT32 bpType = BP_SOFTWARE;
				UINT32 titanType = 0;
				UINT64 origionalBytes = 0;

				// Software BP
				if(nfo.type & BPT_SOFT)
					origionalBytes = get_wide_word((ea_t) absAddr);
				else
				// Hardware BP
				{
					bpType = BP_HARDWARE;

					UINT32 hwType;
					switch (nfo.type)
					{
						case BPT_WRITE: hwType = UE_HARDWARE_WRITE; break;
						case BPT_READ:  continue; break; /*No read type exposed by Titan engine apparently.*/
						case BPT_RDWR:  hwType = UE_HARDWARE_READWRITE; break;
						case BPT_EXEC:  hwType = UE_HARDWARE_EXECUTE; break;
						default: continue; break;
					};
					UINT32 hwSize = (UE_HARDWARE_SIZE_1 + (nfo.size - 1));
					titanType = ((hwType << 4) | hwSize);
				}

				// Write entry
				json_puts(LEVEL2_INDENT "{\n");
					json_format(LEVEL3_INDENT "\"address\": \"0x%llX\",\n", relAddr);
					json_puts(moduleEntry);
					json_puts(LEVEL3_INDENT "\"enabled\": true,\n");
					json_format(LEVEL3_INDENT "\"type\": %u,\n", bpType);
					json_format(LEVEL3_INDENT "\"titantype\": \"0x%X\",\n", titanType);
					json_format(LEVEL3_INDENT "\"oldbytes\": \"0x%llX\"\n", origionalBytes);
				if (i != (count - 1))
				{
					json_puts(LEVEL2_INDENT "},\n");
				}
				else
				{
					json_puts(LEVEL2_INDENT "}\n");
				}
				breakpointCount++;
			}
		}

		ABORT_UPDATE_CHECK();
	}
}

// Return if function name is not autogenerated (probably) by IDA using blacklist patterns
BOOL isUserFunctionName(__in LPCSTR name)
{
	// TODO: Verify the rest strings like "sub_" for a valid follow addresses?

	__try
	{
		UINT64 name64 = *((PUINT64) name);
		UINT32 name32 = (name64 & 0xFFFFFFFF);

		// "sub_" autogenerated function names
		if (name32 == 0x5F627573)
			return FALSE;

		// "SEH_"
		if (name32 == 0x5F484553)
			return FALSE;

		// "$LN" I.E. "$LN21"
		if ((name32 & 0x00FFFFFF) == 0x004E4C24)
			if (isdigit(name[3]))
				return FALSE;

		// "nullsub_"
		if (name64 == 0x5F6275736C6C756E)
			return FALSE;

		// "j_nullsub_
		if (/*"j_nullsu"*/ (name64 == 0x75736C6C756E5F6A) && /*"b_"*/ (*((PWORD) (name + 8)) == 0x5F62))
			return FALSE;

		// "unknown_libname_..
		if (/*"unknown_"*/ (name64 == 0x5F6E776F6E6B6E75) && (*((PUINT64) (name + 8)) == /*"libname_"*/ 0x5F656D616E62696C))
			return FALSE;

		// Skip auto-generated "thunk" stubs
		// "_thunk"
		if ((name64 & 0x0000FFFFFFFFFFFF) == 0x00006B6E7568745F)
			return FALSE;

		// Most likely a user generated name if we made it here
		return TRUE;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	return FALSE;
}

// Return if branch label name is not autogenerated (probably) by IDA using blacklist pattern
BOOL isUserBranchLabel(__in LPCSTR label)
{
	__try
	{
		UINT64 name64 = *((PUINT64) label);
		UINT32 name32 = (name64 & 0xFFFFFFFF);

		// "loc_" autogenerated branch name
		if (name32 == 0x5F636F6C)
			return FALSE;

		// "locret_"
		if ((name64 & 0x00FFFFFFFFFFFFFF) == 0x005F746572636F6C)
			return FALSE;

		// Most likely a user generated name if we made it here
		return TRUE;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	return FALSE;
}

// Fast escape encoding for JSON string values
// Based on: https://github.com/simdjson/simdjson/blob/e27558983290d89db6134e7876830c413902fa3f/include/simdjson/dom/serialization-inl.h#L155
qstring &JsonEscapeEncode(qstring &str)
{
	// Escape encode character map per JSON spec
	static const char ALIGN(16) need_escape[256] =
	{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	// Look for the first character we'd need to escape if any
	size_t size = (str.size() - 1);
	PBYTE input = (PBYTE) str.c_str();
	size_t i = 0;
	for (; (i + 8) <= size; i += 8)
	{
		if (need_escape[input[i + 0]] || need_escape[input[i + 1]] || need_escape[input[i + 2]] || need_escape[input[i + 3]] ||
			need_escape[input[i + 4]] || need_escape[input[i + 5]] || need_escape[input[i + 6]] || need_escape[input[i + 7]]
		   ) { break; }
	}
	for (; i < size; i++)
	{
		if (need_escape[input[i]]) { break; }
	}

	if (i < size)
	{
		// Max output sized buffer as if the remaining output characters had to be all encoded via the "\\u0000" way
		size_t bufferSize = i + ((size - i) * SIZESTR("\\u0000")) + 1;
		auto buf = std::make_unique<BYTE[]>(bufferSize);
		PBYTE output = buf.get();
		if (i > 0)
		{
			memcpy(output, input, i);
			input += i, output += i;
		}
		#define MEMCAT(_input) { memcpy(output, (PBYTE) _input, SIZESTR(_input)); output += SIZESTR(_input); }

		for (; i < size; i++)
		{
			BYTE c = *input++;
			switch (c)
			{
				case '\"':
				MEMCAT("\\\"");
				break;

				case '\\':
				MEMCAT("\\\\");
				break;

				default:
				{
					if (c <= 0x1F)
					{
						#pragma pack(1)
						struct escape_sequence
						{
							BYTE length;
							const char string[7];
						} static const ALIGN(16) escaped[32] =
						{
						  {6, "\\u0000"}, {6, "\\u0001"}, {6, "\\u0002"}, {6, "\\u0003"},
						  {6, "\\u0004"}, {6, "\\u0005"}, {6, "\\u0006"}, {6, "\\u0007"},
						  {2, "\\b"},     {2, "\\t"},     {2, "\\n"},     {6, "\\u000b"},
						  {2, "\\f"},     {2, "\\r"},     {6, "\\u000e"}, {6, "\\u000f"},
						  {6, "\\u0010"}, {6, "\\u0011"}, {6, "\\u0012"}, {6, "\\u0013"},
						  {6, "\\u0014"}, {6, "\\u0015"}, {6, "\\u0016"}, {6, "\\u0017"},
						  {6, "\\u0018"}, {6, "\\u0019"}, {6, "\\u001a"}, {6, "\\u001b"},
						  {6, "\\u001c"}, {6, "\\u001d"}, {6, "\\u001e"}, {6, "\\u001f"}
						};
						#pragma pack()

						auto u = escaped[c];
						memcpy(output, (PBYTE) u.string, u.length);
						output += u.length;
					}
					else
						*output++ = c;
				}
				break;
			};
		}
		*output = 0;

		str = (LPCSTR) buf.get();
		#undef MEMCAT
	}

	return str;
}

// Process name/label
qstring &ProcessLabel(__inout qstring &str, DEMANGLE_OPTION demangle)
{
	// Optionally demangle/undecorate name
	if (demangle == DMO_Demangle)
	{
		LPCSTR mangled = str.c_str();
		qstring demangled;
		int result = demangle_name(&demangled, mangled, (MT_MSCOMP | MNG_SHORT_FORM), DQT_FULL);
		if (result >= 0)
			str = demangled;
	}

	return JsonEscapeEncode(str);
}

// Checks and handles if break key pressed; return TRUE on break.
BOOL checkBreak()
{
	if (!isUserBreak)
	{
		if (WaitBox::isUpdateTime())
		{
			if (WaitBox::updateAndCancelCheck())
			{
				msg("\n*** Aborted ***\n\n");

				// Show stats then directly to exit
				isUserBreak = TRUE;
			}
		}
	}
	return isUserBreak;
}

// ------------------------------------------------------------------------------------------------

// Show about box
void idaapi doRepoLink(int button_code, form_actions_t& fa) { open_url("https://github.com/kweatherman/ida_x64dbgexport_plugin"); }
void idaapi doX64dbgLink(int button_code, form_actions_t& fa) { open_url("https://x64dbg.com/"); }

// https://x64dbg.com/#start
void ShowAboutBox()
{
	const char aboutDialog[] =
	{
		// No cancel button
		"BUTTON CANCEL NONE\n"

		// Title
		"x64db Exporter: About\n"

		// Message text
		"x64dbg exporter plugin %q\n"
		"By Kevin Weatherman 2021. Released under the MIT License.\n"
		"Repo:<#Click to open repo page.#x64dbg_exporter:k::>\n"
		"x64dbg home page:<#Click to open mrexodia's x64dbg home.#x64dbg.com:k::>\n"
	};

	qstring version, tmp;
	version.sprnt("v%s, built %s.", GetVersionString(MY_VERSION, tmp).c_str(), __DATE__);

	ask_form(aboutDialog, &version, doRepoLink, doX64dbgLink);
}

// ------------------------------------------------------------------------------------------------
// IDA menu handler

enum MENU_ACTION
{
	MA_ABOUT,
	MA_EXPORT,
	//MA_IMPORT,
	MA_COUNT
};
#define ENUM2STR(_value) #_value

struct AboutHandler : public action_handler_t
{
	int idaapi activate(action_activation_ctx_t* ctx) override
	{
		ShowAboutBox();
		return 1;
	}

	action_state_t idaapi update(action_update_ctx_t* ctx) override { return AST_ENABLE_FOR_WIDGET; }
};

struct ExportHandler : public action_handler_t
{
	int idaapi activate(action_activation_ctx_t* ctx) override
	{
		__try
		{
			DoExport();
		}
		EXCEPT();
		WaitBox::hide();
		return 1;
	}

	action_state_t idaapi update(action_update_ctx_t* ctx) override { return AST_ENABLE_FOR_WIDGET; }
};

AboutHandler aboutHandler;
ExportHandler exportHandler;
const action_desc_t action[MA_COUNT] =
{
	ACTION_DESC_LITERAL(ENUM2STR(MENU_ACTION::MA_ABOUT),  "About",  &aboutHandler,  "", "About plugin", -1),
	ACTION_DESC_LITERAL(ENUM2STR(MENU_ACTION::MA_EXPORT), "Export x64dbg database", &exportHandler, "", "Export x64dbg database", -1)
};

// ------------------------------------------------------------------------------------------------

plugmod_t* idaapi init()
{
	// Add action menu
	for (UINT32 i = 0; i < MENU_ACTION::MA_COUNT; i++)
	{
		register_action(action[i]);
		attach_action_to_menu(MENU_PATH, action[i].name, SETMENU_APP);
	}

    return PLUGIN_KEEP;
}

// To enable the plugin to be ran from a hotkey
static bool idaapi run(size_t arg)
{	
	__try
	{
		DoExport();
	}
	EXCEPT();
	WaitBox::hide();
	return true;
}

void idaapi term()
{
	// Remove action menu
	for (UINT32 i = 0; i < MENU_ACTION::MA_COUNT; i++)
	{
		detach_action_from_menu(MENU_PATH, action[i].name);
		unregister_action(action[i].name);
	}
}

__declspec(dllexport) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	init,					// Initialize plugin
	term,					// Terminate plugin
	run,					// Invoke plugin
	nullptr,				// Long comment about the plugin
	nullptr,				// Multiline help about the plugin
	"x64dbExport",			// The preferred short name of the plugin
	nullptr					// The preferred hotkey to run the plugin
};
