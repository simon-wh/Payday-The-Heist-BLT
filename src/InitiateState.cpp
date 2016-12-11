#include "InitState.h"

#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include <detours.h>

#include "signatures/signatures.h"
#include "util/util.h"
#include "console/console.h"
#include "threading/queue.h"
#include "http/http.h"

#include <thread>
#include <list>

namespace pd2hook
{
struct lua_State;

typedef const char * (*lua_Reader) (lua_State *L, void *ud, size_t *sz);
typedef int(*lua_CFunction) (lua_State *L);
typedef void * (*lua_Alloc) (void *ud, void *ptr, size_t osize, size_t nsize);
typedef struct luaL_Reg {
	const char* name;
	lua_CFunction func;
} luaL_Reg;

CREATE_NORMAL_CALLABLE_SIGNATURE("lua_call", lua_call, void, "\x8B\x44\x24\x08\x56\x8B\x74\x24\x08\x8B\x56\x08", "xxxxxxxxxxxx", 0, 0x007968C0, lua_State*, int, int)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_pcall", lua_pcall, int, "\x8B\x4C\x24\x10\x83\xEC\x08\x56\x8B\x74\x24\x10", "xxxxxxxxxxxx", 0, 0x0079AF30, lua_State*, int, int, int)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_gettop", lua_gettop, int, "\x8B\x4C\x24\x04\x8B\x41\x08\x2B\x41\x0C", "xxxxxxxxxx", 0, 0x0078F2A0, lua_State*)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_settop", lua_settop, void, "\x8B\x4C\x24\x08\x8B\x44\x24\x04\x85", "xxxxxxxxx", 0, 0x0078F2B0, lua_State*, int)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_tolstring", lua_tolstring, const char*, "\x56\x8B\x74\x24\x08\x57\x8B\x7C\x24\x10\x8B\xCF\x8B\xD6", "xxxxxxxxxxxxxx", 0, 0x00794BA0, lua_State*, int, size_t*)
CREATE_NORMAL_CALLABLE_SIGNATURE("luaL_loadfile", luaL_loadfile, int, "\x81\xEC\x01\x01\x01\x01\x55\x8B\xAC\x24\x01\x01\x01\x01\x56\x8B\xB4\x24\x01\x01\x01\x01\x57", "xx????xxxx????xxxx????x", 0, 0x007A9EC0, lua_State*, const char*)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_load", lua_load, int, "\x8B\x4C\x24\x10\x33\xD2\x83\xEC\x18\x3B\xCA", "xxxxxxxxxxx", 0, 0x007A9E70, lua_State*, lua_Reader, void*, const char*)

CREATE_NORMAL_CALLABLE_SIGNATURE("lua_setfield", lua_setfield, void, "\x8B\x46\x08\x83\xE8\x08\x50\x8D\x4C\x24\x1C", "xxxxxxxxxxx", -53, 0x00797520, lua_State*, int, const char*) //not-unique

CREATE_NORMAL_CALLABLE_SIGNATURE("lua_createtable", lua_createtable, void, "\x83\xC4\x0C\x89\x07\xC7\x47\x04\x05\x00\x00\x00\x83\x46\x08\x08\x5F", "xxxxxxxxx???xxxxx", -66, 0x00794C30, lua_State*, int, int) //not-unique

CREATE_NORMAL_CALLABLE_SIGNATURE("lua_insert", lua_insert, void, "\x8B\x4C\x24\x08\x56\x8B\x74\x24\x08\x8B\xD6\xE8\x50\xFE", "xxxxxxxxxxxxxx", 0, 0x0078F340, lua_State*, int) //overlaps
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_newstate", lua_newstate, lua_State*, "\x53\x55\x8B\x6C\x24\x0C\x56\x57\x8B\x7C\x24\x18\x68\x00\x00\x00\x00\x33\xDB", "xxxxxxxxxxxxx????xx", 0, 0x00799C90, lua_Alloc, void*)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_close", lua_close, void, "\xE9\x00\x00\x00\x00\xCC\xCC\x56\x8B\x71\x70", "x????xxxxxx", 0, 0x00799DD0, lua_State*)

CREATE_NORMAL_CALLABLE_SIGNATURE("lua_rawset", lua_rawset, void, "\x8B\x4C\x24\x08\x53\x56\x8B\x74\x24\x0C\x57", "xxxxxxxxxxx", 0, 0x00792900, lua_State*, int)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_settable", lua_settable, void, "\x8B\x4C\x24\x08\x56\x8B\x74\x24\x08\x8B\xD6\xE8\x00\x00\x00\x00\x8B\x4E\x08\x8D\x51\xF8", "xxxxxxxxxxxx????xxxxxx", 0, 0x00794240, lua_State*, int) //overlaps

CREATE_NORMAL_CALLABLE_SIGNATURE("lua_pushnumber", lua_pushnumber, void, "\x8B\x44\x24\x04\x8B\x48\x08\xF3\x0F\x10\x44\x24\x08", "xxxxxxxxxxxxx", 0, 0x0078F560, lua_State*, double)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_pushinteger", lua_pushinteger, void, "\x8B\x44\x24\x04\x8B\x48\x08\xF3\x0F\x2A\x44\x24\x08", "xxxxxxxxxxxxx", 0, 0x0078F580, lua_State*, ptrdiff_t)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_pushboolean", lua_pushboolean, void, "\x8B\x44\x24\x04\x8B\x48\x08\x33", "xxxxxxxx", 0, 0x0078F5A0, lua_State*, bool)
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_pushcclosure", lua_pushcclosure, void, "\x8B\x50\x04\x8B\x02\x8B\x40\x0C\x8B\x7C\x24\x14\x50\x57\x56", "xxxxxxxxxxxxxxx", -60, 0x007A4260, lua_State*, lua_CFunction, int); //overlaps alot

CREATE_NORMAL_CALLABLE_SIGNATURE("lua_pushlstring", lua_pushlstring, void, "\x52\x50\x56\xE8\x00\x00\x00\x00\x83\xC4\x0C\x89\x07\xC7\x47\x04\x04\x00\x00\x00\x83\x46\x08\x08\x5F", "xxxx????xxxxxxxxx???xxxxx", -58, 0x00797420, lua_State*, const char*, size_t) //not-unique

CREATE_NORMAL_CALLABLE_SIGNATURE("luaI_openlib", luaI_openlib, void, "\x83\xEC\x08\x53\x8B\x5C\x24\x14\x55\x8B\x6C\x24\x1C\x56", "xxxxxxxxxxxxxx", 0, 0x007A43C0, lua_State*, const char*, const luaL_Reg*, int)
CREATE_NORMAL_CALLABLE_SIGNATURE("luaL_ref", luaL_ref, int, "\x53\x8B\x5C\x24\x0C\x8D\x83\x00\x00\x00\x00", "xxxxxxx????", 0, 0x00794310, lua_State*, int);
CREATE_NORMAL_CALLABLE_SIGNATURE("lua_rawgeti", lua_rawgeti, void, "\x8B\x4C\x24\x08\x56\x8B\x74\x24\x08\x8B\xD6\xE8\x00\x00\x00\x00\x8B\x4C\x24\x10", "xxxxxxxxxxxx????xxxx", 0, 0x007928C0, lua_State*, int, int);
CREATE_NORMAL_CALLABLE_SIGNATURE("luaL_unref", luaL_unref, void, "\x53\x8B\x5C\x24\x10\x85\xDB\x7C\x74", "xxxxxxxxx", 0, 0x007943F0, lua_State*, int, int);
CREATE_CALLABLE_CLASS_SIGNATURE("do_game_update", do_game_update, void*, "\xE9\x00\x00\x00\x00\x50\x8B\xF1\x8B\x0E", "x????xxxxx", 0, 0x00747AC0, int*, int*)
CREATE_CALLABLE_CLASS_SIGNATURE("luaL_newstate", luaL_newstate, int, "\xE9\x00\x00\x00\x00\x8B\xF1\x85\xC0\x75\x08", "x????xxxxxx", 0, 0x00779EB0, char, char, int)


// lua c-functions

#define LUA_REGISTRYINDEX	(-10000)
#define LUA_GLOBALSINDEX	(-10002)

// more bloody lua shit
#define LUA_YIELD	1
#define LUA_ERRRUN	2
#define LUA_ERRSYNTAX	3
#define LUA_ERRMEM	4
#define LUA_ERRERR	5
#define LUA_ERRFILE     (LUA_ERRERR+1)

std::list<lua_State*> activeStates;
void add_active_state(lua_State* L){
	activeStates.push_back(L);
}

void remove_active_state(lua_State* L){
	activeStates.remove(L);
}

bool check_active_state(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	std::list<lua_State*>::iterator it;
	for (it = activeStates.begin(); it != activeStates.end(); it++){
		if (*it == L) {
			return true;
		}
	}
	return false;
}

void lua_newcall(lua_State* L, int args, int returns){
	PD2HOOK_TRACE_FUNC;
	int result = lua_pcall(L, args, returns, 0);
	if (result != 0) {
		size_t len;
		PD2HOOK_LOG_ERROR(lua_tolstring(L, -1, &len));
	}
	//PD2HOOK_LOG_LOG("lua call");
}

int luaH_getcontents(lua_State* L, bool files){
	PD2HOOK_TRACE_FUNC;
	size_t len;
	const char* dirc = lua_tolstring(L, 1, &len);
	std::string dir(dirc, len);
	std::vector<std::string> directories;

	try {
		directories = Util::GetDirectoryContents(dir, files);
	}
	catch (const Util::IOException& e){
		PD2HOOK_LOG_EXCEPTION(e);
		lua_pushboolean(L, false);
		return 1;
	}

	lua_createtable(L, 0, 0);

	std::vector<std::string>::iterator it;
	int index = 1;
	for (it = directories.begin(); it < directories.end(); it++){
		if (*it == "." || *it == "..") continue;
		lua_pushinteger(L, index);
		lua_pushlstring(L, it->c_str(), it->length());
		lua_settable(L, -3);
		index++;
	}

	return 1;
}

int luaF_getdir(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	return luaH_getcontents(L, true);
}

int luaF_getfiles(lua_State* L){
	return luaH_getcontents(L, false);
}

int luaF_directoryExists(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	size_t len;
	const char* dirc = lua_tolstring(L, 1, &len);
	bool doesExist = Util::DirectoryExists(dirc);
	lua_pushboolean(L, doesExist);
	return 1;
}

int luaF_unzipfile(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	size_t len;
	const char* archivePath = lua_tolstring(L, 1, &len);
	const char* extractPath = lua_tolstring(L, 2, &len);

	pd2hook::ExtractZIPArchive(archivePath, extractPath);
	return 0;
}

int luaF_removeDirectory(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	size_t len;
	const char* directory = lua_tolstring(L, 1, &len);
	bool success = Util::RemoveEmptyDirectory(directory);
	lua_pushboolean(L, success);
	return 1;
}

int luaF_pcall(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	int args = lua_gettop(L);

	int result = lua_pcall(L, args - 1, -1, 0);
	if (result == LUA_ERRRUN){
		size_t len;
		PD2HOOK_LOG_ERROR(lua_tolstring(L, -1, &len));
		return 0;
	}
	lua_pushboolean(L, result == 0);
	lua_insert(L, 1);

	//if (result != 0) return 1;

	return lua_gettop(L);
}

int luaF_dofile(lua_State* L){
	PD2HOOK_TRACE_FUNC;

	int n = lua_gettop(L);

	size_t length = 0;
	const char* filename = lua_tolstring(L, 1, &length);
	int error = luaL_loadfile(L, filename);
	if (error == LUA_ERRSYNTAX){
		size_t len;
		PD2HOOK_LOG_ERROR(filename << " - " << lua_tolstring(L, -1, &len));
	}
	error = lua_pcall(L, 0, 0, 0);
	if (error == LUA_ERRRUN){
		size_t len;
		PD2HOOK_LOG_ERROR(filename << " - " << lua_tolstring(L, -1, &len));
	}
	return 0;
}

struct lua_http_data {
	int funcRef;
	int progressRef;
	int requestIdentifier;
	lua_State* L;
};

void return_lua_http(void* data, std::string& urlcontents){
	PD2HOOK_TRACE_FUNC;
	lua_http_data* ourData = (lua_http_data*)data;
	if (!check_active_state(ourData->L)) {
		delete ourData;
		return;
	}

	lua_rawgeti(ourData->L, LUA_REGISTRYINDEX, ourData->funcRef);
	lua_pushlstring(ourData->L, urlcontents.c_str(), urlcontents.length());
	lua_pushinteger(ourData->L, ourData->requestIdentifier);
	lua_pcall(ourData->L, 2, 0, 0);
	luaL_unref(ourData->L, LUA_REGISTRYINDEX, ourData->funcRef);
	luaL_unref(ourData->L, LUA_REGISTRYINDEX, ourData->progressRef);
	delete ourData;
}

void progress_lua_http(void* data, long progress, long total){
	PD2HOOK_TRACE_FUNC;
	lua_http_data* ourData = (lua_http_data*)data;

	if (!check_active_state(ourData->L)){
		return;
	}

	if (ourData->progressRef == 0) return;
	lua_rawgeti(ourData->L, LUA_REGISTRYINDEX, ourData->progressRef);
	lua_pushinteger(ourData->L, ourData->requestIdentifier);
	lua_pushinteger(ourData->L, progress);
	lua_pushinteger(ourData->L, total);
	lua_pcall(ourData->L, 3, 0, 0);
}

static int HTTPReqIdent = 0;

int luaF_dohttpreq(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	PD2HOOK_LOG_LOG("Incoming HTTP Request/Request");

	int args = lua_gettop(L);
	int progressReference = 0;
	if (args >= 3){
		progressReference = luaL_ref(L, LUA_REGISTRYINDEX);
	}

	int functionReference = luaL_ref(L, LUA_REGISTRYINDEX);
	size_t len;
	const char* url_c = lua_tolstring(L, 1, &len);
	std::string url = std::string(url_c, len);

	PD2HOOK_LOG_LOG(std::string(url_c, len) << " - " << functionReference);

	lua_http_data* ourData = new lua_http_data();
	ourData->funcRef = functionReference;
	ourData->progressRef = progressReference;
	ourData->L = L;

	HTTPReqIdent++;
	ourData->requestIdentifier = HTTPReqIdent;

	std::unique_ptr<HTTPItem> reqItem(new HTTPItem());
	reqItem->call = return_lua_http;
	reqItem->data = ourData;
	reqItem->url = url;

	if (progressReference != 0){
		reqItem->progress = progress_lua_http;
	}

	HTTPManager::GetSingleton()->LaunchHTTPRequest(std::move(reqItem));
	lua_pushinteger(L, HTTPReqIdent);
	return 1;
}

namespace
{
std::unique_ptr<CConsole> gbl_mConsole;
}

int luaF_createconsole(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	if (!gbl_mConsole)
	{
		gbl_mConsole.reset(new CConsole());
	}
	return 0;
}

int luaF_destroyconsole(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	gbl_mConsole.reset();
	return 0;
}

int luaF_print(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	size_t len;
	const char* str = lua_tolstring(L, 1, &len);
	PD2HOOK_LOG_LUA(str);
	//Logging::Log("aaaaaa", Logging::LOGGING_LUA);
	return 0;
}

int updates = 0;
std::thread::id main_thread_id;

void* __fastcall do_game_update_new(void* thislol, int edx, int* a, int* b){
	// If someone has a better way of doing this, I'd like to know about it.
	// I could save the this pointer?
	// I'll check if it's even different at all later.
	if (std::this_thread::get_id() != main_thread_id){
		return do_game_update(thislol, a, b);
	}

	lua_State* L = reinterpret_cast<lua_State *>(thislol);
	if (updates == 0){
		HTTPManager::GetSingleton()->init_locks();
	}


	if (updates > 1){
		EventQueueMaster::GetSingleton().ProcessEvents();
	}

	updates++;
	return do_game_update(thislol, a, b);
}

// Random dude who wrote what's his face?
// I 'unno, I stole this method from the guy who wrote the 'underground-light-lua-hook'
// Mine worked fine, but this seems more elegant.
int __fastcall luaL_newstate_new(void* thislol, int edx, char no, char freakin, int clue){
	PD2HOOK_TRACE_FUNC;
	int ret = luaL_newstate(thislol, no, freakin, clue);

	lua_State* L = (lua_State*)*((void**)thislol);
	PD2HOOK_LOG_LUA("Lua State: " << L);
	if (!L) return ret;
	//int stack_size = lua_gettop(L);
	//printf("%d\n", stack_size);

	add_active_state(L);

	CREATE_LUA_FUNCTION(luaF_print, "log");
	CREATE_LUA_FUNCTION(luaF_pcall, "pcall");
	CREATE_LUA_FUNCTION(luaF_dofile, "dofile");
	CREATE_LUA_FUNCTION(luaF_unzipfile, "unzip");
	CREATE_LUA_FUNCTION(luaF_dohttpreq, "dohttpreq");

	luaL_Reg consoleLib[] = { { "CreateConsole", luaF_createconsole }, { "DestroyConsole", luaF_destroyconsole }, { NULL, NULL } };
	luaI_openlib(L, "console", consoleLib, 0);

	luaL_Reg fileLib[] = { { "GetDirectories", luaF_getdir }, { "GetFiles", luaF_getfiles }, { "RemoveDirectory", luaF_removeDirectory }, { "DirectoryExists", luaF_directoryExists }, { NULL, NULL } };
	luaI_openlib(L, "file", fileLib, 0);

	//lua_settop(L, stack_size);
	int result;
	PD2HOOK_LOG_LOG("Initiating Hook");

	result = luaL_loadfile(L, "mods/base/base.lua");
	if (result == LUA_ERRSYNTAX){
		size_t len;
		PD2HOOK_LOG_ERROR(lua_tolstring(L, -1, &len));
		return ret;
	}
	result = lua_pcall(L, 0, 1, 0);
	if (result == LUA_ERRRUN){
		size_t len;
		PD2HOOK_LOG_ERROR(lua_tolstring(L, -1, &len));
		return ret;
	}

	//CREATE_LUA_FUNCTION(luaF_pcall, "pcall")
	//CREATE_LUA_FUNCTION(luaF_dofile, "dofile")
	/*CREATE_LUA_FUNCTION(luaF_dohttpreq, "dohttpreq")

	CREATE_LUA_FUNCTION(luaF_unzipfile, "unzip")

	*/
	return ret;
}

void luaF_close(lua_State* L){
	PD2HOOK_TRACE_FUNC;
	remove_active_state(L);
	lua_close(L);
}

void InitiateStates(){
	PD2HOOK_TRACE_FUNC;

	main_thread_id = std::this_thread::get_id();

	SignatureSearch::Search();


	FuncDetour* gameUpdateDetour = new FuncDetour((void**)&do_game_update, do_game_update_new);
	FuncDetour* newStateDetour = new FuncDetour((void**)&luaL_newstate, luaL_newstate_new);
	FuncDetour* luaCallDetour = new FuncDetour((void**)&lua_call, lua_newcall);
	FuncDetour* luaCloseDetour = new FuncDetour((void**)&lua_close, luaF_close);
}

void DestroyStates(){
	PD2HOOK_TRACE_FUNC;
	// Okay... let's not do that.
	// I don't want to keep this in memory, but it CRASHES THE SHIT OUT if you delete this after all is said and done.
	gbl_mConsole.reset();
}
}
