describe("JWT spec", function()

  local jwt = require 'jwt'
  local plainJwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

  it("can decode a plain text token", function()
    local token, msg = jwt.decode(plainJwt)
    assert(token or error(msg))
    assert(token.iss == "joe")
    assert(token.exp == 1300819380)
    assert(token["http://example.com/is_root"] == true)
  end)

  it("can decode a plain text token with an extra dot", function()
    local token, msg = jwt.decode(plainJwt..".")
    assert(token or error(msg))
    assert(token.iss == "joe")
    assert(token.exp == 1300819380)
    assert(token["http://example.com/is_root"] == true)
  end)

  it("can encode a plain text token", function()
    local claim = {
      iss = "joe",
      exp = 1300819380,
      ["http://example.com/is_root"] = true
    }
    local token = jwt.encode(claim)
    local token2 = jwt.encode(jwt.decode(plainJwt))
    assert(token == token2)
  end)

  it("it can encode/decode a signed plain text token with alg=HS256", function()
    local claims = {
      test = "test",
    }
    local token = jwt.encode(claims, {alg = "HS256", keys = {private = "key"}})
    local decodedClaims = jwt.decode(token, {keys = {public = "key"}})
    assert.are.same(claims, decodedClaims)
  end)

  it("it cannot encode/decode a signed plain text token with alg=HS256 and an incorrect key", function()
    local claims = {
      test = "test",
    }
    local token = jwt.encode(claims, {alg = "HS256", keys = {private = "key"}})
    local decodedClaims = jwt.decode(token, {keys = {public = "notthekey"}})
    assert.has_error(function() assert.are.same(claims, decodedClaims) end)
  end)

  it("it can encode/decode a signed plain text token with alg=RS256", function()
    local claims = {
      test = "test",
    }
    local keyPair = crypto.pkey.generate("rsa", 512)
    local token, err = jwt.encode(claims, {alg = "RS256", keys = {private = keyPair}})
    local decodedClaims = jwt.decode(token, {keys = {public = keyPair}})
    assert.are.same(claims, decodedClaims)
  end)

  it("it cannot encode/decode a signed plain text token with alg=RS256 and an incorrect key", function()
    local claims = {
      test = "test",
    }
    local keyPair = crypto.pkey.generate("rsa", 512)
    local badPair = crypto.pkey.generate("rsa", 512)
    local token = jwt.encode(claims, {alg = "RS256", keys = {private = keyPair}})
    local decodedClaims = jwt.decode(token, {keys = {public = badPair}})
    assert.has_error(function() assert.are.same(claims, decodedClaims) end)
  end)
end)
