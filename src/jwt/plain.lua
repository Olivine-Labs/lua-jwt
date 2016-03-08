local basexx  = require 'basexx'
local json    = require 'cjson'
json.encode_empty_table('array')

local data    = {}

function data:encode(header, claims)
  return basexx.to_url64(json.encode(header)) .. "." .. basexx.to_url64(json.encode(claims))
end

function data:decode(header, str, options)
  if options and options.keys then return nil, 'Token is alg=none but keys specified in decode' end
  local dotFirst = str:find("%.")
  str = str:sub(dotFirst+1)
  local dotSecond = str:find("%.")
  if dotSecond then return nil, 'Invalid Token, alg=none but has signature' end
  return json.decode(basexx.from_url64(str))
end

return data
