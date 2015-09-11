module Puppet::Parser::Functions
  newfunction(:merge_array_of_hash, :type => :rvalue, :doc => <<-'ENDHEREDOC') do |args|
    Merges two or more hashes together into an array of hashes and returns the resulting hash merges inside an array.

    For example:

        $hash1 = [{'name' => 'testrule', 'value', => 'testvalue'}, {'name' => 'secondtestrule', 'value' => 'secondtestvalue', 'three' => 'losingthree'}]
        $hash2 = {'two' => 'dos', 'three', => 'tres'}
        $merged_hash = merge($hash1, $hash2)
        # The resulting hash is equivalent to:
        # $merged_hash =  [{'name' => 'testrule', 'value' => 'testvalue', 'two' => 'dos', 'three' => 'tres'}, {'name' => 'secondtestrule', 'value' => 'secondtestvalue', 'two' => 'dos', 'three' => 'tres'}]

    When there is a duplicate key, the key in the rightmost hash will "win."

    ENDHEREDOC

    if args.length < 2
      raise Puppet::ParseError, ("merge(): wrong number of arguments (#{args.length}; must be at least 2)")
    end

    hash_array = args[0]

    # This is just incase they happen to pass us a hash that's not in an array as their source hash
    hash_array = [hash_array] unless hash_array.is_a?(Array)

    result = Array.new

    hash_array.each do |arr|
      next if arr.is_a? String and arr.empty? # empty string is synonym for puppet's undef
      unless arr.is_a?(Hash)
        raise Puppet::ParseError, "merge: unexpected argument type #{arr.class}, only expects hash arguments"
      end
      # Swap args[0] so that we place each hash, one at a time, into the merge loop
      args[0] = arr
      # The hash we accumulate into
      accumulator = Hash.new
      # Merge into the accumulator hash
      args.each do |arg|
        next if arg.is_a? String and arg.empty? # empty string is synonym for puppet's undef
        unless arg.is_a?(Hash)
          raise Puppet::ParseError, "merge: unexpected argument type #{arg.class}, only expects hash arguments"
        end
        accumulator.merge!(arg)
      end
      # Place the fully merged hash into the array
      result << accumulator
    end
    return result
  end
end
