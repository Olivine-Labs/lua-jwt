local basexx  = require 'basexx'
local json    = require 'cjson'
json.encode_empty_table('array')
local digest  = require 'openssl.digest'
local hmac    = require 'openssl.hmac'
local pkey    = require 'openssl.pkey'

local data    = {}

local function tohex(s)
  local result = ""
  for i = 1, #s do
    result = result..string.format("%.2x", string.byte(s, i))
  end
  return result
end

data.sign = {
  ['HS256'] = function(data, key) return tohex(hmac.new(key, 'sha256'):final (data)) end,
  ['HS384'] = function(data, key) return tohex(hmac.new(key, 'sha384'):final (data)) end,
  ['HS512'] = function(data, key) return tohex(hmac.new(key, 'sha512'):final (data)) end,
  ['RS256'] = function(data, key)
    assert(type(key) == "string")
    local ok, result = pcall(function()
      return pkey.new(key):sign(digest.new('sha256'):update(data))
    end)
    if not ok then return nil, result end
    return result
  end,
}

data.verify = {
  ['HS256'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha256'):final (data)) end,
  ['HS384'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha384'):final (data)) end,
  ['HS512'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha512'):final (data)) end,
  ['RS256'] = function(data, signature, key)
    assert(type(key) == "string")
    local ok, result = pcall(function()
      return pkey.new(key):verify(signature, digest.new('sha256'):update(data))
    end)
    if not ok then return nil, result end
    return result
  end,
}

function data:encode(header, claims, options)
  if not options then error("options are required") end
  if not options.keys then error("keys are required") end
  local envelope  = basexx.to_url64(json.encode(header)).."."..basexx.to_url64(json.encode(claims))
  local signature, err = self.sign[header.alg](envelope, options.keys.private)
  if not signature then error('failed to generate signature') end
  return envelope ..'.'..basexx.to_url64(signature)
end

function data:decode(header, str, options)
  local dotFirst = str:find("%.")
  local signature
  local bodyStr
  local rawHeader = str:sub(1, dotFirst-1)
  local str = str:sub(dotFirst+1)
  local dotSecond = str:find("%.")
  if dotSecond then
    bodyStr       = str:sub(1, dotSecond-1)
    if options and options.keys and options.keys.public then
      signature     = basexx.from_url64(str:sub(dotSecond+1))
    end
  else
    if options and options.keys and options.keys.public then
      return nil, "Invalid token"
    end
    bodyStr = str
  end

  local message = basexx.from_url64(bodyStr)
  if signature then
    if not self.verify[header.alg](rawHeader.."."..bodyStr, string.lower(basexx.to_hex(signature)), options.keys.public) then
      return nil, "Token Invalid"
    end
  end

  local decoded_message = json.decode(message)

  if decoded_message.nbf ~= nil then
    if math.floor(ngx.now()) < decoded_message.nbf then
      return nil, "Token not yet valid"
    end
  end

  if decoded_message.exp ~= nil then
    if math.floor(ngx.now()) > decoded_message.exp then
      return nil, "Token expired"
    end
  end

  return decoded_message
end

return data
