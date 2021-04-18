#include <stdint.h>
#include <string.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

const int MAGIC_POINTER = 0x13371337;

int main(int argc, char* argv[]) {
	lua_State *L = luaL_newstate();

	//give command line arguments to the lua script
	lua_createtable(L, argc+1, 0);
	for (int i = 0; i < argc; i++) {
		lua_pushstring(L, argv[i]);
		lua_rawseti(L, -2, i);
	}

	//set cli arguments array as 'arg' global
	lua_setglobal(L, "arg");

	luaL_openlibs(L);
	const char* source = (const char*)MAGIC_POINTER;

	luaL_loadbuffer(L, source, strlen(source), "=lua");
	if (lua_type(L, -1) == LUA_TFUNCTION)
	{
		lua_pcall(L, 0, 0, 0);
		if (lua_gettop(L) > 0)
		{
			printf("%s\n", lua_tostring(L, -1));
		}
	}
	else
	{
		printf("failed to load chunk: %s\n", lua_tostring(L, -1));
	}

	lua_close(L);
	return 0;
}
