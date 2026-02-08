#!/usr/bin/env luajit
local ffi = require 'ffi'
local path = require 'ext.path'
local number = require 'ext.number'
local assert = require 'ext.assert'
local vector = require 'stl.vector-lua'

local datafile, patchfile, outfile, showall  = ...
-- showall = if this is empty then truncate long output strings
if not datafile or not patchfile or not outfile then
	local expectedStr = 'expected ips <datafile> <patchfile> <outfile>\n'
		..'got '..table.concat(arg, ' ')
	io.stderr:write(expectedStr, '\n')
	os.exit(1)
end

local data = assert(path(datafile):read())
local patch = assert(path(patchfile):read())

local datav = vector('uint8_t', #data)
ffi.copy(datav.v, data, #data)

local verbose = not ipsOnProgress -- if no callback then print

local function rawToNumber(d)
	-- msb first
	local v = 0
	for i=1,#d do
		v = v * 256
		v = v + d:sub(i,i):byte()
	end
	return v
end

-- coroutines plz
local patchIndex = 0
local function readPatchChunk(size)
	local chunk = patch:sub(patchIndex+1, patchIndex + size)
	assert.len(chunk, size, "readPatchChunk: stepped past the end of the file")
	patchIndex = patchIndex + size
	if ipsOnProgress then	--external callback
		ipsOnProgress(patchIndex,#patch)
	end
	return chunk
end

local function readPatchValue(ctype)
	local size = ffi.sizeof(ctype)
	assert.le(patchIndex + size, #patch, "readPatchValue: stepped past the end of the patch file")
	local value = rawToNumber(patch:sub(patchIndex+1, patchIndex + size))
	patchIndex = patchIndex + size
	if ipsOnProgress then	--external callback
		ipsOnProgress(patchIndex,#patch)
	end
	return value
end

-- offset is 1-based
local function replaceSubset(d, repl, offset)
	if offset <= #d then
		d = d:sub(1, offset-1) .. repl .. d:sub(offset + #repl)
	else
		d = d .. string.char(0):rep(offset - #d - 1) .. repl
	end
	return d
end

local function hex(v, max)
	local n = number.hex(v, max)
	return ('0'):rep(max-#n)..n
end

local function strtohex(s, max)
	local d = ''
	if showall or not max then
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

local function readVarInt()
	local v = 0
	local ofs = 1
	while true do
		local n = readPatchValue'uint8_t'
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
	assert.len(data, datasize, "data file")
	local targetsize = readVarInt()
	local target = ('\0'):rep(targetsize)
	assert.len(target, targetsize, "target")
	local metadatasize = readVarInt()
	local metadata = readPatchChunk(metadatasize)
	assert.len(metadata, metadatasize , "metadata")
	print(metadata)

	local writeOffset = 0
	local sourceRelativeOffset = 0
	local targetRelativeOffset = 0
	while writeOffset < targetsize do
		local value = readVarInt()
		local op = bit.band(value, 3)
		local length = bit.rshift(value, 2) + 1
print('ofs '..hex(writeOffset)..'/'..hex(targetsize)..' op '..op..' len '..hex(length))
		if op == 0 then		-- source read
			--target_buf[writeOffset:writeOffset+item.bytespan] = source_buf[writeOffset:writeOffset+item.bytespan]
			target = replaceSubset(target, data:sub(writeOffset+1, writeOffset+length), writeOffset+1)
			assert.len(target, targetsize, "target")
		elseif op == 1 then	-- target read
			local subpatch = readPatchChunk(length)
			--target_buf[writeOffset:writeOffset+item.bytespan] = item.payload
			target = replaceSubset(target, subpatch, writeOffset+1)
			assert.len(target, targetsize, "target")
		elseif op == 2 then	-- source copy
			local raw_offset = readVarInt()
			local offset = bit.rshift(raw_offset, 1)
			if bit.band(raw_offset, 1) ~= 0 then offset = -offset end
			sourceRelativeOffset = sourceRelativeOffset + offset
			-- target_buf[writeOffset:writeOffset+item.bytespan] = source_buf[item.offset:item.offset+item.bytespan]
			target = replaceSubset(target, data:sub(sourceRelativeOffset+1, sourceRelativeOffset+length), writeOffset+1)
			assert.len(target, targetsize, "target")
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
	path(outfile):write(target)
else
	sig = sig .. readPatchChunk(1)
	assert.eq(sig, 'PATCH', "signature")
	if verbose then
		print('got sig '..sig)
	end
	while true do
		local offset = readPatchChunk(3)
		if offset == 'EOF' then
			if verbose then
				print('got EOF')
			end
			break
		end	-- what if you want an offset that has this value? ips limitations...
		offset = rawToNumber(offset)
		local size = readPatchValue'uint16_t'
print('offset', number.hex(offset), 'size', number.hex(size))
		if size > 0 then
			local subpatch = readPatchChunk(size)
			if verbose then
				print('patching offset '..hex(offset, 3)..' size '..hex(size, 2)..' data '..strtohex(subpatch, 10))
			end
			data = replaceSubset(data, subpatch, offset+1)
		else	--RLE
			local rleSize = readPatchValue'uint16_t'
			local value = readPatchChunk(1)
			if verbose then
				print('patching offset '..hex(offset, 3)..' size '..hex(size, 2)..' value '..strtohex(value))
			end
			data = replaceSubset(data, value:rep(rleSize), offset+1)
		end
	end

	path(outfile):write(data)
end
