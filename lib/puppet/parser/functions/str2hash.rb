#
# str2hash.rb
#
require 'json'

module Puppet::Parser::Functions
  newfunction(:str2hash, :type => :rvalue, :doc => <<-EOS
This converts a string to a hash. This attempt to convert strings that
represent hashes, in any form, back to hash.
    EOS
  ) do |arguments|

    raise(Puppet::ParseError, "str2hash(): Wrong number of arguments " +
      "given (#{arguments.size} for 1)") if arguments.size < 1

    string = arguments[0]

    # If string is already Hash, return it
    if string.is_a?(Hash)
      return string
    end

    unless string.is_a?(String)
      raise(Puppet::ParseError, 'str2hash(): Requires either ' +
        'string to work with')
    end

    # If the string is a hash inside an array representation, we clear the array part
    string.sub!(/^\[(\{.*\})\]$/,'\1')

    # Transform object string symbols to quoted strings
    string.gsub!(/([{,]\s*):([^>\s]+)\s*=>/, '\1"\2"=>')
    
    # Transform object string numbers to quoted strings
    string.gsub!(/([{,]\s*)([0-9]+\.?[0-9]*)\s*=>/, '\1"\2"=>')
    
    # Transform object value symbols to quotes strings
    string.gsub!(/([{,]\s*)(".+?"|[0-9]+\.?[0-9]*)\s*=>\s*:([^,}\s]+\s*)/, '\1\2=>"\3"')
    
    # Transform array value symbols to quotes strings
    string.gsub!(/([\[,]\s*):([^,\]\s]+)/, '\1"\2"')
    
    # Transform object string object value delimiter to colon delimiter
    string.gsub!(/([{,]\s*)(".+?"|[0-9]+\.?[0-9]*)\s*=>/, '\1\2:')
    
    begin
      result = JSON.parse(string)
    rescue
      raise(Puppet::ParseError, 'str2hash(): Unknown type of hash given')
    end

    return result
  end
end

# vim: set ts=2 sw=2 et :
