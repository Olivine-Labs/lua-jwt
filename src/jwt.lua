local meta    = {}
local data    = {}

local json    = require 'cjson'
local basexx  = require 'basexx'
local jws     = require 'jwt.jws'
local jwe     = require 'jwt.jwe'
local plain   = require 'jwt.plain'

local function getJwt(options)
  if options and options.alg and options.alg ~= "none" then
    if options.enc then
      return jwe
    else
      return jws
    end
  else
    return plain
  end
end

function meta:__metatable()
  return false
end

function meta:__index(key)
  return data[key]
end

local function header(options)
  if options then
    return {
      alg = options.alg,
      enc = options.enc,
      iss = options.iss,
      aud = options.aud,
      sub = options.sub,
    }
  end
  return {}
end

function data.encode(claims, options)
  local jwt       = getJwt(options)
  local header    = header(options)
  local token, err = jwt:encode(header, claims, options)
  if not token then return nil, err end
  return token:gsub('+','-'):gsub('/','_'):gsub('=','')
end

function data.decode(str, options)
  if not str then return nil, "Parameter 1 cannot be nil" end
  local dotFirst = str:find("%.")
  if not dotFirst then return nil, "Invalid token" end
  str = str:gsub('-','+'):gsub('_','/')
  local mod = #str % 3
  if mod == 1 then str = str..'='
  elseif mod == 2 then str = str..'==' end
  local header = json.decode((basexx.from_base64(str:sub(1,dotFirst-1))))

  return getJwt(header):decode(header, str, options)
end

function meta:__newindex(key)
  error('Read Only')
end

return setmetatable({}, meta)
