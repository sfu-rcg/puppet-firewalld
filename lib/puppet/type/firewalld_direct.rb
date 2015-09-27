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

    def insync?(is)
      #@should = resource.should_content('chains')
      puts "INSYNC chains:\nIS: #{is}\nSH: #{@should}"
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

    def should_to_s(s)
      if s.is_a?(Array)
        s
      else
        [s]
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

    validate do |val|
      puts "VALIDATE #{val.inspect}"
      val = [val] unless val.is_a?(Array)
      val.each do |rule|
        if rule and not rule.empty?
          fail("#{rule} is missing required parameter: ipv.") unless rule['ipv']
          fail("#{rule} is missing required parameter: table.") unless rule['table']
          fail("#{rule} is missing required parameter: chain.") unless rule['chain']
          fail("#{rule} is missing required parameter: args.") unless rule['args']
        end
      end
    end

    def insync?(is)
      #@should = resource.should_content('rules')
      puts "INSYNC rules:\nIS: #{is}\nSH: #{@should}"
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

    def should_to_s(s)
      if s.is_a?(Array)
        s
      else
        [s]
      end
    end
  end

  newproperty(:passthroughs, :array_matching => :all) do
    desc "Read only attribute. Represents all of the passthroughs from all firewalld_direct resources."

    def insync?(is)
      #@should = resource.should_content('passthroughs')
      puts "INSYNC passthroughs:\nIS: #{is}\nSH: #{@should}"
      self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
      if @should.empty? && is == :absent then
        return true
      end
      @should = @should.uniq
      @should = @should.flatten


      puts "#{is.length} - #{@should.length}"
      puts "#{is == @should} - #{is == @should.map(&:to_s)}"
      if match_all? then
        return false unless is.is_a? Array
        return false unless is.length == @should.length
        return (is == @should or is == @should.map(&:to_s))
      else
        return @should.any? {|want| property_matches?(is, want) }
      end
    end

    def should_to_s(s)
      if s.is_a?(Array)
        s
      else
        [s]
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
end
