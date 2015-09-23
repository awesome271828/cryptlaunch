#!/usr/bin/env ruby

require 'openssl'

ITERATIONS = 10000

program = File.read(ARGV[0])

print 'Password: '

system('stty -echo')
password = STDIN.gets.chomp
system('stty echo')

puts

cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt

salt = OpenSSL::Random.random_bytes(32)

key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, 32, OpenSSL::Digest::SHA512.new)

cipher.key = key

iv = cipher.random_iv

IO.write('program', cipher.update(program) + cipher.final)
IO.write('tag', cipher.auth_tag)
IO.write('salt', salt)
IO.write('iv', iv)

%w[program tag salt iv].each do |name|
	system("objcopy --input binary --output elf64-x86-64 --binary-architecture i386 #{name} #{name}.o")
end

system("./build.sh")
