# encoding:utf-8

require 'active_model'
require 'ipaddress'

# Validator for email
class IpValidator < ActiveModel::EachValidator

  def forbidden
    unless @forbidden.is_a? Array
      if options[:forbidden].nil?
        # default
        @forbidden = []
      else
        @forbidden = options[:forbidden].is_a?(Array) ? options[:forbidden] : [options[:forbidden]]
      end
    end
    @forbidden
  end

  def forbidden? key
    forbidden.include? key
  end

  # main validator for email
  def validate_each(record, attribute, value)
    unless value.blank?

      # pre var
      valid = true

      begin
        ip = IPAddress.parse(value.to_s)

        valid = false if forbidden? :netmask and value =~ /\//
        valid = false if forbidden? :a and ip.a?
        valid = false if forbidden? :b and ip.b?
        valid = false if forbidden? :c and ip.c?
        valid = false if forbidden? :ipv4 and ip.class == IPAddress::IPv4
        valid = false if forbidden? :ipv6 and (ip.class == IPAddress::IPv6 or ip.class == IPAddress::IPv6::Mapped)
        if options[:custom].is_a? Proc
          valid = false unless options[:custom].call(ip) 
        end
      rescue
        valid = false
      end

      # ip valid
      record.errors.add(attribute, :invalid) unless valid
    end
  end
end
