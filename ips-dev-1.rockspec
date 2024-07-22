package = "ips"
version = "dev-1"
source = {
	url = "git+https://github.com/thenumbernine/lua-ips"
}
description = {
	detailed = "I got bored of running Lunar's IPS utility in Wine/VM so I wrote my own IPS tool in Lua.",
	homepage = "https://github.com/thenumbernine/lua-ips",
	license = "MIT"
}
dependencies = {
	"lua >= 5.1"
}
build = {
	type = "builtin",
	modules = {
		["ips.addheader"] = "addheader.lua",
		["ips"] = "ips.lua",
		["ips.makeips"] = "makeips.lua"
	}
}
