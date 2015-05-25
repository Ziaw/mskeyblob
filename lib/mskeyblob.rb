require 'mskeyblob/version'

module OpenSSL
  module PKey
    class RSA
      RSA1 = 0x31415352
      RSA2 = 0x32415352

      PUBLICKEYBLOB = 0x6
      PRIVATEKEYBLOB = 0x7

      CALG_RSA_KEYX = 0x0000a400

      def self.from_mskeyblob(key)
        b_type, b_version, reserved, alg_id,  # PUBLICKEYSTRUC
            magic, bit_len, public_exponent,  # RSAPUBKEY
            rest =
            key.unpack('CCSL LLL a*')

        # PUBLICKEYBLOB || PRIVATEKEYBLOB
        raise OpenSSL::PKey::RSAError, "Neither PUB key nor PRIV key: invalid bType #{b_type}" unless [PUBLICKEYBLOB, 0x7].include? b_type
        raise OpenSSL::PKey::RSAError, "Neither PUB key nor PRIV key: invalid bVersion #{b_version}" unless b_version == 2
        raise OpenSSL::PKey::RSAError, "Neither PUB key nor PRIV key: invalid magic #{magic}" unless [RSA1, RSA2].include? magic

        b8 = "a#{bit_len / 8}"
        b16 = "a#{bit_len / 16}"

        unpack_pattern = [b8, b16, b16, b16, b16, b16, b8].join('')

        modulus, p1, p2, e1, e2, c, private_exponent = rest.unpack(unpack_pattern)

        modulus, p1, p2, e1, e2, c, private_exponent = [modulus, p1, p2, e1, e2, c, private_exponent].map  do |byte_array|
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

      def to_mskeyblob(include_private: :not_set)
        if include_private == :not_set
          include_private = private?
        else
          if include_private && !private?
            raise OpenSSL::PKey::RSAError, 'Public key can not export private part'
          end
        end

        b_type = include_private ? PRIVATEKEYBLOB : PUBLICKEYBLOB
        b_version = 2
        reserved = 0
        alg_id = CALG_RSA_KEYX
        magic = include_private ? RSA2 : RSA1


        bit_len = n.num_bits # https://github.com/ruby/openssl/issues/5
        public_exponent = e

        b8 = "a#{bit_len / 8}"
        b16 = "a#{bit_len / 16}"

        header = [
            b_type, b_version, reserved, alg_id,  # PUBLICKEYSTRUC
            magic, bit_len, public_exponent,      # RSAPUBKEY
        ].pack('CCSL LLL')

        modulus, p1, p2, e1, e2, c, private_exponent = [n, p, q, dmp1, dmq1, iqmp, d].map  do |bn|
          if bn
            bn.to_s(2).reverse
          else
            nil
          end
        end

        if include_private
          pack_pattern = [b8, b16, b16, b16, b16, b16, b8].join('')

          header + [modulus, p1, p2, e1, e2, c, private_exponent].pack(pack_pattern)
        else
          header + [modulus].pack(b8)
        end
      end
    end
  end
end
