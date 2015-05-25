# Microsoft RSA key blob

    Exchange RSA keys between Microsoft CSP blob format (ExportCspBlob, ImportCspBlob of RSACryptoServiceProvider)
    and ruby openssl key OpenSSL::PKey::RSA

## Installation

Add this line to your application's Gemfile:

    gem 'mskeyblob'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install mskeyblob

## Usage

Create key from blob created by ExportCspBlob

```ruby
    blob = File.binread 'msblob.bin'

    key = OpenSSL::PKey::RSA.from_mskeyblob blob
```    

Create blob for ExportCspBlob

```ruby
    key = OpenSSL::PKey::RSA.new 2048

    blob = key.to_mskeyblob
    public_blob = key.to_mskeyblob(include_private: false)
```

## Contributing

1. Fork it ( https://github.com/Ziaw/mskeyblob/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request


## Links

1. [MSDN Enhanced Provider Key BLOBs](https://msdn.microsoft.com/en-us/library/windows/desktop/aa382021%28v=vs.85%29.aspx)

2. [Ruby and OpenSSL](http://blog.flame.org/2009/02/28/ruby-and-openssl.html)