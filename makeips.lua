#!/usr/bin/env lua

args = {...}

require 'ext'

expectedStr = 'expected ips <modified> <original> <patch>, got '..table.concat(args, ' ')
modifiedFileName = assert(args[1], expectedStr)
originalFileName = assert(args[2], expectedStr)
patchFileName = assert(args[3], expectedStr)

modifiedData = assert(path(modifiedFileName):read())
originalData = assert(path(originalFileName):read())

local nextModified, nextOriginal	-- chars, empty if EOF has been hit, nil if both EOFs have been hit
local charProcessorIndex	-- zero-based
local charProcessor = coroutine.create(function()
	charProcessorIndex = 0
	while charProcessorIndex < #modifiedData
	or charProcessorIndex < #originalData
	do
		-- I really would use coroutine.yield, but as lexers go, you need a N-state buffer ... here's my 1-state buffer:
		nextModified = modifiedData:csub(charProcessorIndex, 1)	--csub is sub but (0-based-first, size) rather than (1-based-first, 1-based-last)
		nextOriginal = originalData:csub(charProcessorIndex, 1)	-- (so it's similar to C-style 0-based-addressing)
--		if nextModified ~= nextOriginal then print('char '..charProcessorIndex..' differ') end
		-- so what's there to yield?
		coroutine.yield()
		charProcessorIndex = charProcessorIndex + 1
	end
	nextModified = nil
	nextOriginal = nil
end)
-- get the first chunk
charProcessor:resume()

patch = table()

function numberToRaw(n, size)
	local s = table()
	for i=1,size do
		local b = n % 256
		n = n - b
		n = n / 256
		assert(n == math.floor(n))
		s:insert(1, string.char(b))	-- first byte is most-significant
	end
	assert(n == 0)
	return s:concat()
end

function processDifference()
	local location = charProcessorIndex
	print('patch start '..location)
	local thisPatch = table{nextModified}
	while true do
		charProcessor:resume()
		if nextModified == ''		-- modified EOF ... should this happen? can IPS support shrinking files?
		or nextModified == nil		-- both EOF's
		or nextModified == nextOriginal -- equality -- our difference stretch has stopped
		or charProcessorIndex - location >= 65535 
		then
			break
		end
		thisPatch:insert(nextModified)
	end
	print('patch end '..charProcessorIndex)
	local size = charProcessorIndex - location
	assert(size == #thisPatch, "patch size is "..#thisPatch.." loc diff is "..size)
	assert(size <= 65536, "patch is too big")

	local entry = table()
	entry:insert(numberToRaw(location, 3))
	entry:insert(numberToRaw(size, 2))
	entry:insert(thisPatch:concat())
	entry = entry:concat()
	
	patch:insert(entry)
end

patch:insert('PATCH')

-- cycle through the two files
while nextModified ~= nil do
	if nextModified ~= nextOriginal then
		processDifference()
	else
		charProcessor:resume()
	end
end

patch:insert('EOF')
patch = patch:concat()

path(patchFileName):write(patch)
