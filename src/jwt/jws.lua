local basexx  = require 'basexx'
local json    = require 'cjson'
local crypto  = require 'crypto'

local data    = {}

data.sign = {
  ['HS256'] = function(data, key) return crypto.hmac.digest('sha256', data, key) end,
  ['HS384'] = function(data, key) return crypto.hmac.digest('sha384', data, key) end,
  ['HS512'] = function(data, key) return crypto.hmac.digest('sha512', data, key) end,
  ['RS256'] = function(data, key) return crypto.sign("sha256", data, key) end,
}

data.verify = {
  ['HS256'] = function(data, signature, key) return signature == crypto.hmac.digest('sha256', data, key) end,
  ['HS384'] = function(data, signature, key) return signature == crypto.hmac.digest('sha384', data, key) end,
  ['HS512'] = function(data, signature, key) return signature == crypto.hmac.digest('sha512', data, key) end,
  ['RS256'] = function(data, signature, key)
    local pubkey = type(key) == "userdata" and key or crypto.pkey.from_pem(key)
    return crypto.verify("sha256", data, signature, pubkey)
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
    if not self.verify[header.alg](rawHeader.."."..bodyStr, signature, options.keys.public) then
      return nil, "Invalid token"
    end
  end

  return json.decode(message)
end

return data
