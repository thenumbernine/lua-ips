#!/usr/bin/env lua

args = args or {...}

require 'ext'

expectedStr = 'expected ips <datafile> <patchfile> <outfile>, got '..table.concat(args, ' ')
datafile = assert(args[1], expectedStr)
patchfile = assert(args[2], expectedStr)
outfile = assert(args[3], expectedStr)

data = assert(io.readfile(datafile))
patch = assert(io.readfile(patchfile))

local verbose = not ipsOnProgress -- if no callback then print

-- coroutines plz
patchIndex = 1
function readPatchChunk(size)
	local chunk = assert(patch:sub(patchIndex, patchIndex + size - 1), "stepped past the end of the file")
	patchIndex = patchIndex + size
	if ipsOnProgress then	--external callback
		ipsOnProgress(patchIndex,#patch)
	end
	return chunk
end

function rawToNumber(d)
	-- msb first
	local v = 0
	for i=1,#d do
		v = v * 256
		v = v + d:sub(i,i):byte()
	end
	return v
end

-- offset is 1-based
function replaceSubset(d, repl, offset)
	if offset <= #d then
		d = d:sub(1, offset-1) .. repl .. d:sub(offset + #repl)
	else
		d = d .. string.char(0):rep(offset - #d - 1) .. repl
	end
	return d
end

function hex(v,s)
	if not s then s = 1 end
	s = s * 2
	return string.format('%.'..s..'x', v)
end

function strtohex(s, max)
	local d = ''
	if not max then
		max = #s
	else
		if max > #s then max = #s end
	end
	for i=1,max do
		local v = s:sub(i,i):byte()
		d = d .. hex(v, 1)
	end
	if max < #s then d = d .. '...' end
	return d
end

local signature = readPatchChunk(5)
assert(signature == 'PATCH', "got bad signature: "..tostring(signature))

while true do
	local offset = readPatchChunk(3)
	if offset == 'EOF' then
		if verbose then
			print('got EOF')
		end
		break
	end	-- what if you want an offset that has this value? ips limitations...
	offset = rawToNumber(offset)
	local size = rawToNumber(readPatchChunk(2))
	if size > 0 then
		local subpatch = readPatchChunk(size)
		if verbose then
			print('patching offset '..hex(offset, 3)..' size '..hex(size, 2)..' data '..strtohex(subpatch, 10))
		end
		data = replaceSubset(data, subpatch, offset+1)
	else	--RLE
		local rleSize = rawToNumber(readPatchChunk(2))
		local value = readPatchChunk(1)
		if verbose then
			print('patching offset '..hex(offset, 3)..' size '..hex(size, 2)..' value '..strtohex(value))
		end
		data = replaceSubset(data, value:rep(rleSize), offset+1)
	end
end

io.writefile(outfile, data)
