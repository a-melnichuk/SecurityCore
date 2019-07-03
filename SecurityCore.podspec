Pod::Spec.new do |s|
  s.name         = "SecurityCore"
  s.version      = "0.0.3"
  s.summary      = "SecurityCore"
  s.homepage     = "https://paytomat.com/"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.authors      = {
    "Vitalii Havryliuk" => "v.havryliuk@noisyminer.com",
    "Alex Melnichuk" => "a.melnichuk@yahoo.com"
  }
  s.source       = { :git => 'https://github.com/a-melnichuk/SecurityCore.git' }
  s.source_files = [
    'SecurityCore/*.h',
    'SecurityCore/Sources/*.swift',
    'SecurityCore/Sources/Services/*.swift',
    'SecurityCore/Sources/Security Providers/*.swift'
  ]
  s.platform     = :ios
  s.ios.deployment_target = '10.0'
  s.swift_version = '5.0'
  s.frameworks = 'Foundation', 'LocalAuthentication'
end
