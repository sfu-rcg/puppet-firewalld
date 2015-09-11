#
# hash_deep_sort.rb
#
class Hash
  def deep_sort
    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
  end
end

module Puppet::Parser::Functions
  newfunction(:hash_deep_sort, :type => :rvalue, :doc => <<-EOS
This will sort your supplied hash all levels deep based on key name
    EOS
  ) do |arguments|

    raise(Puppet::ParseError, "hash_deep_sort(): Wrong number of arguments " +
      "given (#{arguments.size} for 1)") if arguments.size != 1

    hash = arguments[0]

    unless hash.is_a?(Hash)
      raise(Puppet::ParseError, 'hash_deep_sort(): Requires a ' +
        'hash to work with')
    end

    hash.deep_sort
  end
end

# vim: set ts=2 sw=2 et :
