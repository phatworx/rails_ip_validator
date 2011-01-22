# encoding: utf-8

require 'helper'

class ValidateIp
  include ActiveModel::Validations
  attr_accessor :ip
end

class ValidateIpDefault < ValidateIp
  validates :ip, :ip => true
end

class ValidateIpCustom < ValidateIp
  validates :ip, :ip => {:custom => Proc.new { |ip| ip.prefix == 24 }}
end

class ValidateIpForbiddenPrivate < ValidateIp
  validates :ip, :ip => {:forbidden => :private}
end

class ValidateIpForbiddenA < ValidateIp
  validates :ip, :ip => {:forbidden => :a}
end

class ValidateIpForbiddenB < ValidateIp
  validates :ip, :ip => {:forbidden => :b}
end

class ValidateIpForbiddenC < ValidateIp
  validates :ip, :ip => {:forbidden => :c}
end

class ValidateIpForbiddenIpv4 < ValidateIp
  validates :ip, :ip => {:forbidden => :ipv4}
end

class ValidateIpForbiddenIpv6 < ValidateIp
  validates :ip, :ip => {:forbidden => :ipv6}
end

class ValidateIpForbiddenNetmask < ValidateIp
  validates :ip, :ip => {:forbidden => :netmask}
end

class TestRailsIpValidator < Test::Unit::TestCase

  def get_ipv4s
    [
        '0.0.0.0',
        '127.0.0.1',
        '88.88.88.88',
        '10.0.0.1',
        '172.16.0.1',
        '192.168.0.1',
        '192.167.10.2/24'
    ]
  end

  def get_ipv6s
    [
        1,
        '123',
        '::',
        '::1',
        '::/128',
        'ac10:0a01',
        '::ffff:192.168.0.1',
        '1080:0000:0000:0000:0008:0800:200c:417a',
        '1080::8:800:200c:417a',
        '1080::8:800:200c:417a/64',
        '2001:db8:0:cd30::',
        '0000:0000:0000:0000:0000:0000:0000:0000'
    ]
  end

  def test_default_validations
    instance = ValidateIpDefault.new
    (get_ipv4s + get_ipv6s).each do |ip|
      instance.ip = ip
      assert instance.valid?, ip.to_s
    end
  end

  def test_invalid_ips
    instance = ValidateIpDefault.new
    [
        '127.0.0.',
        '127.0.0.a',
        '127.0.0.1/a',
        'sdfsd',
        '1123.123.123.123',
        3.3
    ].each do |ip|
      instance.ip = ip
      assert !instance.valid?, ">>#{ip.to_s}<<"
    end
  end

  def test_custom
    instance = ValidateIpCustom.new
    [
        '192.168.10.1/24',
        '127.0.0.1/24'
    ].each do |ip|
      instance.ip = ip
      assert instance.valid?, ip.to_s
    end

    instance = ValidateIpCustom.new
    [
        '192.168.10.1/32',
        '127.0.0.1/32'
    ].each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end
  end

  def test_forbidden_a
    klass    = ValidateIp
    instance = ValidateIpForbiddenA.new
    [
        '10.0.0.1',
        '::ffff:10.0.0.1'
    ].each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end
  end

  def test_forbidden_b
    instance = ValidateIpForbiddenB.new
    [
        '172.16.0.1',
        '::ffff:172.16.0.1'
    ].each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end
  end

  def test_forbidden_c
    instance = ValidateIpForbiddenC.new
    [
        '192.168.0.1',
        '::ffff:192.168.0.1'
    ].each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end
  end

  def test_forbidden_private
    instance = ValidateIpForbiddenPrivate.new
    [
        '10.0.0.1',
        '::ffff:10.0.0.1',
        '172.16.0.1',
        '::ffff:172.16.0.1',
        '192.168.0.1',
        '::ffff:192.168.0.1'
    ].each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end
  end

  def test_forbidden_ipv4
    instance = ValidateIpForbiddenIpv4.new
    get_ipv4s.each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end
    get_ipv6s.each do |ip|
      instance.ip = ip
      assert instance.valid?, ip.to_s
    end
  end

  def test_forbidden_ipv6
    instance = ValidateIpForbiddenIpv6.new
    get_ipv4s.each do |ip|
      instance.ip = ip
      assert instance.valid?, ip.to_s
    end
    get_ipv6s.each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end
  end

  def test_forbidden_c
    instance = ValidateIpForbiddenNetmask.new
    [
        '192.168.0.1/12',
        '::ffff:192.168.0.1/12'
    ].each do |ip|
      instance.ip = ip
      assert !instance.valid?, ip.to_s
    end

    [
        '192.168.0.1',
        '::ffff:192.168.0.1'
    ].each do |ip|
      instance.ip = ip
      assert instance.valid?, ip.to_s
    end
  end
end
