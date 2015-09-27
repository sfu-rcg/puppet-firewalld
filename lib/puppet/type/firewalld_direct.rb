require 'puppet'

class Hash
  def deep_sort
    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
  end
end

Puppet::Type.newtype(:firewalld_direct) do
  desc <<-EOT
          = Define firewalld::direct
          Direct rule (firewalld.direct(5)
          Each section of, chain, rule or passthrough is optional.

          === Examples
         
          class {'firewalld::direct':
            chains  => [
              {
                ipv   => 'ipv4',
                table => 'filter',
                chain => 'mine',
              },
            ],
         
            rules => [
              {
                ipv      => 'ipv4',
                table    => 'filter',
                chain    => 'mine',
                priority => '1',
                args     => "-j LOG --log-prefix 'my prefix'",
              },
              {
                ipv      => 'ipv4',
                table    => 'mangle',
                chain    => 'PREROUTING',
                args     => "-p tcp -m tcp --dport 123 -j MARK --set-mark 1",
              },
            ],
          }
  EOT

  #ensurable do
  #  defaultvalues
  #  defaultto { :present }
  #end

  newparam(:name) do
    desc "The name of the direct rule, must be unique"
  end
 
  newparam(:chains, :array_matching => :all) do
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
    defaultto ([])
    def munge(s)
      if !s.nil? or !s.empty?
        if s.is_a?(Hash)
          [s.deep_sort]
        else
          s.map! { |x| x.deep_sort }
        end
      else
        [s]
      end
    end
    def insync?(is)
      self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
      if @should.empty? && is == :absent then
        return true
      end

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

  newparam(:rules, :array_matching => :all) do
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
    defaultto ([])

    def munge(s)
      if !s.nil? or !s.empty?
        if s.is_a?(Hash)
          [s.deep_sort]
        else
          s.map! { |x| x.deep_sort }
        end
      else
        [s]
      end
    end
    def insync?(is)
      self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
      if @should.empty? && is == :absent then
        return true
      end

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

  newparam(:passthroughs, :array_matching => :all) do
    desc <<-EOT
      list of iptables chains to create 
      passthroughs  => [
        {
          ipv   => 'ipv4',
          args  => "-A IN_passthrough -s 0.0.0.0/0 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT",
        },
      ],
    EOT
    defaultto ([])
    def munge(s)
      if !s.nil? or !s.empty?
        if s.is_a?(Hash)
          [s.deep_sort]
        else
          s.map! { |x| x.deep_sort }
        end
      else
        [s]
      end
    end
    def insync?(is)
      self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
      if @should.empty? && is == :absent then
        return true
      end

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
end
