require 'mskeyblob/version'
require 'base64'

OpenSSL::PKey::RSA.class_eval do
  def self.from_mskeyblob(key)
    b_type, b_version, reserved, alg_id,  # PUBLICKEYSTRUC
        magic, bit_len, public_exponent,  # RSAPUBKEY
        rest =
        key.unpack('CCSL LLL a*')

    b8 = "a#{bit_len / 8}"
    b16 = "a#{bit_len / 16}"

    unpack_pattern = [b8, b16, b16, b16, b16, b16, b8, 'a*'].join('')

    modulus, p1, p2, e1, e2, c, private_exponent, rest = rest.unpack(unpack_pattern).map do |byte_array|
      if byte_array.empty?
        nil
      else
        OpenSSL::BN.new byte_array.reverse, 2
      end
    end

    key = OpenSSL::PKey::RSA.new
    key.n = modulus
    key.e = public_exponent

    if private_exponent
      key.d = private_exponent
      key.p = p1
      key.q = p2
      key.dmp1 = e1
      key.dmq1 = e2
      key.iqmp = c
    end

    key
  end
end