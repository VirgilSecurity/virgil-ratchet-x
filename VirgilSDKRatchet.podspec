Pod::Spec.new do |s|
  s.name                        = "VirgilSDKRatchet"
  s.version                     = "0.10.0"
  s.swift_version               = "5.0"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Virgil SDK for communication using Double Ratchet protocol for Apple devices and languages."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-ratchet-x/"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-ratchet-x.git", :tag => s.version }
  s.ios.deployment_target       = "11.0"
  s.osx.deployment_target       = "10.13"
  s.tvos.deployment_target      = "11.0"
  s.watchos.deployment_target   = "4.0"
  s.source_files                = 'Source/**/*.{h,m,swift}'
  s.dependency "VirgilCryptoRatchet", "= 0.17.0"
  s.dependency "VirgilSDK", "= 9.0.0"
end
