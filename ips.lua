#!/usr/bin/env luajit

local bit = bit32 or require 'bit'

args = args or {...}

require 'ext'

expectedStr = 'expected ips <datafile> <patchfile> <outfile>, got '..table.concat(args, ' ')
datafile = assert(args[1], expectedStr)
patchfile = assert(args[2], expectedStr)
outfile = assert(args[3], expectedStr)

data = assert(file[datafile])
patch = assert(file[patchfile])

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

function readVarInt()
	local v = 0
	local ofs = 1
	while true do
		local n = rawToNumber(readPatchChunk(1))
		v  = v + bit.band(n, 0x7f) * ofs
		if bit.band(n, 0x80) ~= 0 then break end
		ofs = bit.lshift(ofs, 7)
		v = v + ofs
	end
	return v
end

local isBPS
local sig = readPatchChunk(4)
if sig == 'BPS1' then
	isBPS = true
	print'file is BPS'
	local datasize = readVarInt()
	assert(datasize == #data, "data file should be size "..datasize.." but actually is size "..#data)
	local targetsize = readVarInt()
	local target = ('\0'):rep(targetsize)
	assert(#target == targetsize)
	local metadatasize = readVarInt()
	local metadata = readPatchChunk(metadatasize)
	assert(#metadata == metadatasize , "metadata should be size "..metadatasize.." but actually is size "..#metadata)
	print(metadata)
	
	local writeOffset = 0
	local sourceRelativeOffset = 0
	local targetRelativeOffset = 0
	while writeOffset < targetsize do
		local value = readVarInt()
		local op = bit.band(value, 3)
		local length = bit.rshift(value, 2) + 1
print('ofs '..hex(writeOffset)..' op '..op..' len '..hex(length))
		if op == 0 then		-- source read
			--target_buf[writeOffset:writeOffset+item.bytespan] = source_buf[writeOffset:writeOffset+item.bytespan]
			target = replaceSubset(target, data:sub(writeOffset+1, writeOffset+length), writeOffset+1)
			assert(#target == targetsize)
		elseif op == 1 then	-- target read
			local subpatch = readPatchChunk(length)
			--target_buf[writeOffset:writeOffset+item.bytespan] = item.payload
			target = replaceSubset(target, subpatch, writeOffset+1)
			assert(#target == targetsize)
		elseif op == 2 then	-- source copy
			local raw_offset = readVarInt()
			local offset = bit.rshift(raw_offset, 1)
			if bit.band(raw_offset, 1) ~= 0 then offset = -offset end
			sourceRelativeOffset = sourceRelativeOffset + offset 
			-- target_buf[writeOffset:writeOffset+item.bytespan] = source_buf[item.offset:item.offset+item.bytespan]
			target = replaceSubset(target, data:sub(sourceRelativeOffset+1, sourceRelativeOffset+length), writeOffset+1)
			assert(#target == targetsize)
			sourceRelativeOffset = sourceRelativeOffset + length  
		elseif op == 3 then	-- target copy
			local raw_offset = readVarInt()
			local offset = bit.rshift(raw_offset, 1)
			if bit.band(raw_offset, 1) ~= 0 then offset = -offset end
			targetRelativeOffset = targetRelativeOffset + offset
			for i=1,length do
				target = replaceSubset(target, target:sub(targetRelativeOffset+i,targetRelativeOffset+i), writeOffset+i+1)
			end
		end
		writeOffset = writeOffset + length
	end
print'done'	
	file[outfile] = target
else
	sig = sig .. readPatchChunk(1)
	assert(sig == 'PATCH', "got bad signature: "..tostring(sig))

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

	file[outfile] = data
end
