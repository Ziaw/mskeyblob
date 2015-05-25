require 'test/unit'
require 'mskeyblob'
require 'base64'

class TestActor < Test::Unit::TestCase
  TEST_DATA = 'test'
  ENCRYPTED_TEST_DATA = Base64.decode64 'RqcD37GZP0D3T24GEU+xEI9v8D/jKpwIFhD37EJ/MBMF82MqeyJ/RN689UExT2kzuOt8CqIA2S6c9xXVxw4aWTPJq8jJO431yFvSYQBNGyQ6jkPCE5s2TW8HI5vxWiaGkIdR6wJJP2KtDr5s0BsspjDmH2dNlQ6sPnkKJJEaxuS041PjwA8F+gEKbbwCmOc5hs4J8yQfBezn61VXYXzRDDSUtYhhscko9Nb44O9fXRcLh0KXr2nqZcn16pWalwHvx9zBt9EROlCRJmGPXBZPmXdtTgGNZZqaaca+3p5VjXN652sdT4EQX52sKLWBLSiwHD+u15NoAJ8BcQwBnW8Nng=='

  def test_private_key_from_mskeyblob
    base = File.dirname(__FILE__)
    msblob = File.binread(File.join(base, 'fixtures', 'msblob'))

    key = OpenSSL::PKey::RSA.from_mskeyblob msblob

    assert_not_nil key
    assert key.private?

    pem = File.read(File.join(base, 'fixtures', 'pem'))
    pem_key = OpenSSL::PKey::RSA.new pem

    assert_equal key.n, pem_key.n
    assert_equal key.e, pem_key.e
    assert_equal key.d, pem_key.d
    assert_equal key.p, pem_key.p
    assert_equal key.q, pem_key.q
    assert_equal key.dmp1, pem_key.dmp1
    assert_equal key.dmq1, pem_key.dmq1
    assert_equal key.iqmp, pem_key.iqmp

    assert_equal key.private_decrypt(key.public_encrypt(TEST_DATA)), TEST_DATA
    assert_equal key.public_decrypt(key.private_encrypt(TEST_DATA)), TEST_DATA

    assert_equal key.private_decrypt(ENCRYPTED_TEST_DATA), TEST_DATA
  end

  def test_private_key_to_mskeyblob
    base = File.dirname(__FILE__)
    msblob = File.binread(File.join(base, 'fixtures', 'msblob'))
    pem = File.read(File.join(base, 'fixtures', 'pem'))

    pem_key = OpenSSL::PKey::RSA.new pem

    assert_equal pem_key.to_mskeyblob, msblob

    msblob = File.binread(File.join(base, 'fixtures', 'msblob.pub'))
    assert_equal pem_key.to_mskeyblob(include_private: false), msblob
  end

  def test_public_key_from_mskeyblob
    base = File.dirname(__FILE__)
    msblob = File.binread(File.join(base, 'fixtures', 'msblob.pub'))

    key = OpenSSL::PKey::RSA.from_mskeyblob msblob

    assert_not_nil key
    assert key.public?
    assert !key.private?

    pem = File.read(File.join(base, 'fixtures', 'pem'))
    pem_key = OpenSSL::PKey::RSA.new pem

    assert_equal key.n, pem_key.n
    assert_equal key.e, pem_key.e

    assert_equal key.public_decrypt(pem_key.private_encrypt(TEST_DATA)), TEST_DATA
  end

  def test_public_key_to_mskeyblob
    base = File.dirname(__FILE__)
    msblob = File.binread(File.join(base, 'fixtures', 'msblob.pub'))
    pem = File.read(File.join(base, 'fixtures', 'pem.pub'))

    pem_key = OpenSSL::PKey::RSA.new pem

    assert_equal pem_key.to_mskeyblob, msblob
  end
end