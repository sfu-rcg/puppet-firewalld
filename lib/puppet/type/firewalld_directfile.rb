require 'puppet/util/checksums'

class Hash
  def deep_sort
    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
  end
end

Puppet::Type.newtype(:firewalld_directfile) do
  @doc = "Gets all the direct rule fragments and puts these into the direct.xml file."

  ensurable do
    defaultvalues

    defaultto { :present }
  end

  ## the file/posix provider will check for the :links property
  ## which does not exist
  #def [](value)
  #  return false if value == :links
  #  super
  #end

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
    defaultto do
      # only be executed if no :content is set
      @chains_default = true
      @resource.no_content
    end

    validate do |val|
      fail "read-only attribute" unless @chains_default
    end

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
      @should = resource.should_content('chains')
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
    defaultto do
      # only be executed if no :content is set
      @rules_default = true
      @resource.no_content
    end

    validate do |val|
      fail "read-only attribute" unless @rules_default
    end

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
      @should = resource.should_content('rules')
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

    include Puppet::Util::Diff

    defaultto do
      # only be executed if no :content is set
      @passthroughs_default = true
      @resource.no_content
    end

    validate do |val|
      fail "read-only attribute" unless @passthroughs_default
    end
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
      @should = resource.should_content('passthroughs')
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

#  newproperty(:content) do
#    desc "Read only attribute. Represents the content."
#
#    include Puppet::Util::Diff
#
#    defaultto do
#      # only be executed if no :content is set
#      @content_default = true
#      @resource.no_content
#    end
#
#    validate do |val|
#      fail "read-only attribute" unless @content_default
#    end
#
#    def insync?(is)
#      result = super
#      string_file_diff(@resource[:path], @resource.should_content) if result
#      result
#    end
#  end

  def no_content
    #"\0PLEASE_MANAGE_THIS_WITH_FIREWALLD_DIRECTFILE\0"
    []
  end

  def should_content(property_type)
    gen_resource = instance_variable_get("@generated_" + property_type)
    return gen_resource if gen_resource
    @generated_chains = ""
    @generated_rules = "" 
    @generated_passthroughs = "" 
    direct_chains = []
    direct_rules = []
    direct_passthroughs = []

    resources = catalog.resources.select do |r|
      r.is_a?(Puppet::Type.type(:firewalld_direct))# && r[:tag] == self[:tag]
    end

    resources.each do |r|
      direct_chains << r[:chains] if r[:chains]
      direct_rules << r[:rules] if r[:rules]
      direct_passthroughs << r[:passthroughs] if r[:passthroughs]
    end

    @generated_chains = direct_chains
    @generated_rules = direct_rules 
    @generated_passthroughs = direct_passthroughs 

    # This should return the instance variable for whatever called it
    # Should really only get to this point the first time around as we set all instance variables during one run
    # The rest of the calls to this method should return on the second line which contains the return if not undef
    instance_variable_get("@generated_" + property_type)
  end

  def stat(*)
    return @stat if @stat && !@stat == :needs_stat
    @stat = begin
      ::File.stat(self[:path])
    rescue Errno::ENOENT
      nil
    rescue Errno::EACCES
      warning "Could not stat; permission denied"
      nil
    end
  end

  ### took from original type/file
  # There are some cases where all of the work does not get done on
  # file creation/modification, so we have to do some extra checking.
  def property_fix
    properties.each do |thing|
      next unless [:mode, :owner, :group].include?(thing.name)

      # Make sure we get a new stat object
      @stat = :needs_stat
      currentvalue = thing.retrieve
      thing.sync unless thing.safe_insync?(currentvalue)
    end
  end
end
