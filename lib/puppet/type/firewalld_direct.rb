require 'puppet/util/checksums'

Puppet::Type.newtype(:firewalld_direct) do
  @doc = "Gets all the direct rule fragments and puts these into the direct.xml file."

  ensurable do
    defaultvalues

    defaultto { :present }
  end

  newparam(:name, :namevar => true) do
    desc "The name of the direct rule, must be unique"
  end

  newproperty(:chains, :array_matching => :all) do
    desc <<-EOT
      list of iptables chains to create
      chains  => [
        {
          ipv   => 'ipv4',
          table => 'filter',
          chain => 'mine',
        },
      ],
    EOT

    validate do |chain|
      if chain and not chain.empty?
        fail("#{chain} is missing required parameter: ipv.") unless chain['ipv']
        fail("#{chain} is missing required parameter: chain.") unless chain['chain']
      end
    end

    munge do |chain|
      # Here we deal with optional params and add them if they're not specified
      if chain and not chain.empty?
        chain['table'] ||= 'filter'
      end
      chain
    end

    def insync?(is)
      self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
      if @should.empty? && is == :absent then
        return true
      end
      @should = @should.uniq
      @should = @should.flatten

      if match_all? then
        return false unless is.is_a? Array
        return false unless is.length == @should.length
        return (is == @should or is == @should.map(&:to_s))
      else
        return @should.any? {|want| property_matches?(is, want) }
      end
    end

    def is_to_s(currentvalue)
      if provider.respond_to?(:direct_is_to_s)
        provider.direct_is_to_s(self.name)
      else
        super(currentvalue)
      end
    end

    def should_to_s(newvalue)
      if provider.respond_to?(:direct_should_to_s)
        provider.direct_should_to_s(self.name)
      else
        super(newvalue)
      end
    end

    def change_to_s(currentvalue, newvalue)
      if provider.respond_to?(:direct_change_to_s)
        # In this case we don't need the current and newvalue.  We are caching this inside our provider using a class instance variable
        provider.direct_change_to_s(self.name)
      else
        super(currentvalue,newvalue)
      end
    end
  end

  newproperty(:rules, :array_matching => :all) do
    desc <<-EOT
      list of direct iptables rules to create using straight args provided
      rules => [
        {
          ipv      => 'ipv4',
          table    => 'filter', # optional, will default to 'filter'
          chain    => 'mine',
          priority => '1', # lowest numbered priority comes first in iptables list
          args     => "-j LOG --log-prefix 'my prefix'",
        },
        {
          ipv      => 'ipv4',
          table    => 'mangle',
          chain    => 'PREROUTING',
          args     => "-p tcp -m tcp --dport 123 -j MARK --set-mark 1",
        },
      ],
    EOT

    validate do |rule|
      if rule and not rule.empty?
        fail("#{rule} is missing required parameter: ipv.") unless rule['ipv']
        fail("#{rule} is missing required parameter: chain.") unless rule['chain']
        fail("#{rule} is missing required parameter: args.") unless rule['args']
      end
    end

    munge do |rule|
      # Here we deal with optional params and add them if they're not specified
      if rule and not rule.empty?
        rule['table'] ||= 'filter'
        rule['priority'] ||= '0'
      end
      rule
    end

    def insync?(is)
      self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
      if @should.empty? && is == :absent then
        return true
      end
      @should = @should.uniq
      @should = @should.flatten

      if match_all? then
        return false unless is.is_a? Array
        return false unless is.length == @should.length
        return (is == @should or is == @should.map(&:to_s))
      else
        return @should.any? {|want| property_matches?(is, want) }
      end
    end

    def is_to_s(currentvalue)
      if provider.respond_to?(:direct_is_to_s)
        provider.direct_is_to_s(self.name)
      else
        super(currentvalue)
      end
    end

    def should_to_s(newvalue)
      if provider.respond_to?(:direct_should_to_s)
        provider.direct_should_to_s(self.name)
      else
        super(newvalue)
      end
    end

    def change_to_s(currentvalue, newvalue)
      if provider.respond_to?(:direct_change_to_s)
        # In this case we don't need the current and newvalue.  We are caching this inside our provider using a class instance variable
        provider.direct_change_to_s(self.name)
      else
        super(currentvalue,newvalue)
      end
    end
  end

  newproperty(:passthroughs, :array_matching => :all) do
    desc "Represents all of the passthroughs from all firewalld_direct resources."

    validate do |passthrough|
      if passthrough and not passthrough.empty?
        fail("#{passthrough} is missing required parameter: ipv.") unless passthrough['ipv']
        fail("#{passthrough} is missing required parameter: args.") unless passthrough['args']
      end
    end

    def insync?(is)
      self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
      if @should.empty? && is == :absent then
        return true
      end
      @should = @should.uniq
      @should = @should.flatten

      if match_all? then
        return false unless is.is_a? Array
        return false unless is.length == @should.length
        return (is == @should or is == @should.map(&:to_s))
      else
        return @should.any? {|want| property_matches?(is, want) }
      end
    end

    def is_to_s(currentvalue)
      if provider.respond_to?(:direct_is_to_s)
        provider.direct_is_to_s(self.name)
      else
        super(currentvalue)
      end
    end

    def should_to_s(newvalue)
      if provider.respond_to?(:direct_should_to_s)
        provider.direct_should_to_s(self.name)
      else
        super(newvalue)
      end
    end

    def change_to_s(currentvalue, newvalue)
      if provider.respond_to?(:direct_change_to_s)
        # In this case we don't need the current and newvalue.  We are caching this inside our provider using a class instance variable
        provider.direct_change_to_s(self.name)
      else
        super(currentvalue,newvalue)
      end
    end
  end

  autorequire(:component) do
    ipset_arr = []
    self[:rules].each do |rule|
      if /-m\s+set.*--match-set\s+(.*?)\s+/.match(rule['args'])
        if result = catalog.resource("Ipset[#{$1}]")
          ipset_arr << result
        else
          raise(Puppet::Error.new("#{self.path}: specified rules['args'] with --match-set: #{$1}, but the node's catalog does not contain that Ipset"))
        end
      end
    end
    ipset_arr
  end

  def should_content(property_type)
    # This method is used from inside the provider if needed in order to create the file if it doesn't exist
    # Should be rarely called but is required to exist.
    gen_resource = instance_variable_get("@generated_" + property_type)
    return gen_resource if gen_resource
    @generated_chains = {}
    @generated_rules = {}
    @generated_passthroughs = {}
    direct_chains = []
    direct_rules = []
    direct_passthroughs = []

    resources = catalog.resources.select do |r|
      r.is_a?(Puppet::Type.type(:firewalld_direct))
    end

    resources.each do |r|
      @generated_chains[r.name] = r[:chains] if r[:chains]
      @generated_rules[r.name] = r[:rules] if r[:rules]
      @generated_passthroughs[r.name] = r[:passthroughs] if r[:passthroughs]
    end

    # This should return the instance variable for whatever called it
    # Should really only get to this point the first time around as we set all instance variables during one run
    # The rest of the calls to this method should return on the second line which contains the return if not undef
    instance_variable_get("@generated_" + property_type)
  end
end
