assert(#arg >= 2, "expected <infile> <outfile>")
local infile = arg[1]
local outfile = arg[2]

local path = require 'ext.path'

local d = path(infile):read()
assert(#d % 0x1000 == 0, "found a header of size "..(#d % 0x1000))

local s8k = math.floor(#d / (8*1024))
local losize = s8k % 0x100
local hisize = math.floor(s8k / 0x100) % 0x100
local flags = 0

local header = string.char(losize) .. string.char(hisize) .. string.char(flags) .. string.char(0):rep(509)
assert(#header == 0x200)

path(outfile):write(header .. d)
