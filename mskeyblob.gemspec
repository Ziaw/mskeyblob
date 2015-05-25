# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'mskeyblob/version'

Gem::Specification.new do |spec|
  spec.name          = "mskeyblob"
  spec.version       = Mskeyblob::VERSION
  spec.authors       = ["Alexander Zimin"]
  spec.email         = ["ziminav@gmail.com"]
  spec.summary       = %q{Using Microsoft crypto service provider RSA blob format.}
  spec.description   = %q{Exchange RSA keys between Microsoft CSP blob format (ExportCspBlob, ImportCspBlob) and ruby openssl key OpenSSL::PKey::RSA}
  spec.homepage      = "https://github.com/Ziaw/mskeyblob"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "pry"
end
