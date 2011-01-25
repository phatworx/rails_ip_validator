# encoding: utf-8
require 'helper'

#class TestRailsIpValidator < Test::Unit::TestCase
  describe "rails ip validator" do
    before do
      class ValidateIp
        include ActiveModel::Validations
        attr_accessor :ip
      end
    end

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

    describe "default ip validation" do

      before do
        class ValidateIpDefault < ValidateIp
          validates :ip, :ip => true
        end
        @object = ValidateIpDefault.new
      end

      describe "test with valid ips" do
        it "should validate without errors" do
          (get_ipv4s + get_ipv6s).each do |ip|
            @object.ip = ip
            assert @object.valid?, ip.to_s
          end
        end
      end

      describe "test with invalid ips" do
        it "should validate with error" do
          [
              '127.0.0.',
              '127.0.0.a',
              '127.0.0.1/a',
              'sdfsd',
              '1123.123.123.123',
              3.3
          ].each do |ip|
            @object.ip = ip
            assert !@object.valid?, ">>#{ip.to_s}<<"
          end
        end
      end

    end

    describe "custom validation" do
      before do
        class ValidateIpCustom < ValidateIp
          validates :ip, :ip => {:custom => Proc.new { |ip| ip.prefix == 24 }}
        end
        @object = ValidateIpCustom.new
      end

      describe "test with valid ips" do
        it "should validate without errors" do
          [
              '192.168.10.1/24',
              '127.0.0.1/24'
          ].each do |ip|
            @object.ip = ip
            assert @object.valid?, ip.to_s
          end
        end
      end


      describe "test with invalid ips" do
        it "should validate with error" do
          [
              '192.168.10.1/32',
              '127.0.0.1/32'
          ].each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end
    end


    describe "forbidden a network" do
      before do
        class ValidateIpForbiddenA < ValidateIp
          validates :ip, :ip => {:forbidden => :a}
        end
        @object = ValidateIpForbiddenA.new
      end

      describe "test with b addresses" do
        it "should validate with errors" do
          [
              '10.0.0.1',
              '::ffff:10.0.0.1'
          ].each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end
    end

    describe "forbidden b network" do
      before do
        class ValidateIpForbiddenB < ValidateIp
          validates :ip, :ip => {:forbidden => :b}
        end
        @object = ValidateIpForbiddenB.new
      end

      describe "test with b addresses" do
        it "should validate with errors" do
          [
              '172.16.0.1',
              '::ffff:172.16.0.1'
          ].each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end
    end

    describe "forbidden c network" do
      before do
        class ValidateIpForbiddenC < ValidateIp
          validates :ip, :ip => {:forbidden => :c}
        end
        @object = ValidateIpForbiddenC.new
      end

      describe "test with c addresses" do
        it "should validate with errors" do
          [
              '192.168.0.1',
              '::ffff:192.168.0.1'
          ].each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end
    end

    describe "forbidden private network" do
      before do
        class ValidateIpForbiddenPrivate < ValidateIp
          validates :ip, :ip => {:forbidden => :private}
        end
        @object = ValidateIpForbiddenPrivate.new
      end

      describe "test with private addresses" do
        it "should validate with errors" do
          [
              '10.0.0.1',
              '::ffff:10.0.0.1',
              '172.16.0.1',
              '::ffff:172.16.0.1',
              '192.168.0.1',
              '::ffff:192.168.0.1'
          ].each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end
    end

    describe "forbidden ipv4 network" do
      before do
        class ValidateIpForbiddenIpv4 < ValidateIp
          validates :ip, :ip => {:forbidden => :ipv4}
        end
        @object = ValidateIpForbiddenIpv4.new
      end

      describe "test with ipv4 addresses" do
        it "should validate with errors" do
          get_ipv4s.each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end

      describe "test with ipv6 addresses" do
        it "should validate without errors" do
          get_ipv6s.each do |ip|
            @object.ip = ip
            assert @object.valid?, ip.to_s
          end
        end
      end
    end

    describe "forbidden ipv6 network" do
      before do
        class ValidateIpForbiddenIpv6 < ValidateIp
          validates :ip, :ip => {:forbidden => :ipv6}
        end
        @object = ValidateIpForbiddenIpv6.new
      end

      describe "test with ipv4 addresses" do
        it "should validate without errors" do
          get_ipv4s.each do |ip|
            @object.ip = ip
            assert @object.valid?, ip.to_s
          end
        end
      end

      describe "test with ipv6 addresses" do
        it "should validate with errors" do
          get_ipv6s.each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end
    end

    describe "forbidden netmask" do
      before do
        class ValidateIpForbiddenNetmask < ValidateIp
          validates :ip, :ip => {:forbidden => :netmask}
        end
        @object = ValidateIpForbiddenNetmask.new
      end

      describe "test with netmask" do
        it "should validate with errors" do
          [
              '192.168.0.1/12',
              '::ffff:192.168.0.1/12'
          ].each do |ip|
            @object.ip = ip
            assert !@object.valid?, ip.to_s
          end
        end
      end

      describe "test with netmask" do
        it "should validate without errors" do
          [
              '192.168.0.1',
              '::ffff:192.168.0.1'
          ].each do |ip|
            @object.ip = ip
            assert @object.valid?, ip.to_s
          end
        end
      end
    end
  end
#end