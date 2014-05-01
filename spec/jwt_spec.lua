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
  it("can verify a signature", function()
    local token = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJhOGZjZTFkZi1iNGFlLTRjNDEtYmFjNi1iNWJiZjI4MGMyOWMiLCJzdWIiOiI3YmZjNThlYy03N2RkLTQ4NzQtYmViZC1iYTg0MTAzMDEyNzkiLCJzY29wZSI6WyJvYXV0aC5hcHByb3ZhbHMiLCJvcGVuaWQiXSwiY2xpZW50X2lkIjoibG9naW4iLCJjaWQiOiJsb2dpbiIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiI3YmZjNThlYy03N2RkLTQ4NzQtYmViZC1iYTg0MTAzMDEyNzkiLCJ1c2VyX25hbWUiOiJhZG1pbkBmb3Jpby5jb20iLCJlbWFpbCI6ImFkbWluQGZvcmlvLmNvbSIsImlhdCI6MTM5ODkwNjcyNywiZXhwIjoxMzk4OTQ5OTI3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojk3NjMvdWFhL29hdXRoL3Rva2VuIiwiYXVkIjpbIm9hdXRoIiwib3BlbmlkIl19.xOa5ZpXksgoaA_XJ3yHMjlLcbSoM6XJy-e60zfyP7bRmu0EKEGZdZrl2iJVh6OTIn8z6UuvcY282C1A5LtRgpir4wqhIrphd-Mi9gfxra0pJvtydd4XqVpuNdW7GDaC43VXpvUtetmfn-YAo2jkD9G22mUuT2sFdt5NqFL7Rk4tVRILes73OWxfQpuoReWvRBik-sJXxC9ADmTuzR36OvomIrso42R8aufU2ku_zPve8IhYLvn3vHmYCt0zNZkX-jSV8YtGodr9V-dKs9na41YvGp2UxkBcV7LKoGSRELSSNJ8JLF-bjO3zYSSbT42-yeHeKfoWAeP6R7S_0c_AYRA"
    local key = [[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3h3hbKXM40yH18djU0eM
asMIJ2jEtRn4DzJEcPvRDu+zFUzzNqSUFbD6pYIv/S+C31edIvyfi9kxMdZOKEIm
AHasLJ6PTBej+ruzIWHNf2Yse7+egXEit5bcKb3J9FOpCDHE+YjM4S9QaQT2hr30
Y7iIVcNURJn0k2T6HL+AVt0oUbupUdJjS9S5GUSQ0F74t74J9g7X4sOSTjl3RBxB
mUzfYor3w1HVwP+R0awAzSlNYZdWWJJM6aZXH76nqfv6blKTW0on12b71YWRWKYP
GxG1KwES6v5+PeLzlJDIDRcI8pl49fJYoXyasF8pskS63o9q8ibQspk+nzL9lD4E
EQIDAQAB
-----END PUBLIC KEY-----]]

    local claims = jwt.decode(token, {keys={public=key}})
    assert(claims)
  end)
end)
