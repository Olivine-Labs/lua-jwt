local function prequire(mod)
  local ok, m = pcall(require, mod)
  if not ok then return nil, m end
  return m
end

local json = prequire "cjson"
if json and json.encode_empty_table then
  json.encode_empty_table('array')
else
  json = require "dkjson"
end

local HMAC, DIGEST
local pkey_new, pkey_sign, pkey_verify

local function tohex(s)
  local result = ""
  for i = 1, #s do
    result = result..string.format("%.2x", string.byte(s, i))
  end
  return result
end

if prequire "openssl.digest" then -- luaossl
  local digest  = require 'openssl.digest'
  local hmac    = require 'openssl.hmac'
  local pkey    = require 'openssl.pkey'

  HMAC = {
    SHA256 = function(data, key, hex)
      local s = hmac.new(key, 'sha256'):final (data)
      if hex then s = tohex(s) end
      return s
    end;
    SHA384 = function(data, key, hex)
      local s = hmac.new(key, 'sha384'):final (data)
      if hex then s = tohex(s) end
      return s
    end;
    SHA512 = function(data, key, hex)
      local s = hmac.new(key, 'sha512'):final (data)
      if hex then s = tohex(s) end
      return s
    end;
  }

  DIGEST = {
    SHA256 = function(data, hex)
      local s = digest.new('sha256'):update (data)
      if hex then s = tohex(s) end
      return s
    end;
    SHA384 = function(data, hex)
      local s = digest.new('sha384'):update (data)
      if hex then s = tohex(s) end
      return s
    end;
    SHA512 = function(data, hex)
      local s = digest.new('sha512'):update (data)
      if hex then s = tohex(s) end
      return s
    end;
  }

  pkey_sign = function(digest, key, data)
    data = DIGEST[digest](data, false)
    return pkey.new(key):sign(data)
  end

  pkey_verify = function(digest, key, signature, data)
    data = DIGEST[digest](data, false)
    return pkey.new(key):verify(signature, data)
  end

  pkey_new = function(t)
    return pkey.new(t)
  end
else -- lua-openssl
  local openssl = require "openssl"
  local digest  = assert(openssl.digest)
  local hmac    = assert(openssl.hmac)
  local pkey    = assert(openssl.pkey)

  HMAC = {
    SHA256 = function(data, key, hex) return hmac.digest('sha256', key, data, not hex) end;
    SHA384 = function(data, key, hex) return hmac.digest('sha384', key, data, not hex) end;
    SHA512 = function(data, key, hex) return hmac.digest('sha512', key, data, not hex) end;
  }

  DIGEST = {
    SHA256 = function(data, hex) return digest.digest('sha256', data, not hex) end;
    SHA384 = function(data, hex) return digest.digest('sha384', data, not hex) end;
    SHA512 = function(data, hex) return digest.digest('sha512', data, not hex) end;
  }

  pkey_sign = function(digest, key, data)
    key = assert(pkey.read(key, true))
    return pkey.sign(key, data, digest)
  end

  pkey_verify = function(digest, key, signature, data)
    key = assert(pkey.read(key, false))
    return pkey.verify(key, data, signature, digest)
  end

  pkey_new = function(t)
    return pkey.new(t.type, t.bits)
  end
end

return {
  HMAC     = HMAC;
  DIGEST   = DIGEST;
  json     = json;
  pkey     = {
    new    = pkey_new;
    verify = pkey_verify;
    sign   = pkey_sign
  };
}
