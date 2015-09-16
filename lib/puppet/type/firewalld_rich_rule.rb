require 'puppet'

class Hash
  def deep_sort
    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
  end
end

Puppet::Type.newtype(:firewalld_rich_rule) do
  desc <<-EOT
          Rich language rule (firewalld.richlanguage(5)
          You have to specify one (and only one)
          of service, port, protocol, icmp_block, masquerade, forward_port
          and one (and only one) of accept, reject, drop
  EOT

  ensurable do
    defaultvalues

    defaultto { :present }
  end

  def exists?
    self[:ensure] == :present
  end


#  ensurable do
#    defaultvalues
#    defaultto do
#      puts "Resource zone ensurable: #{resource[:zone]}"
##      zone = self[:zone]
##      rich_rules = self[:rich_rules]
##      puts "Zone: #{zone}"
##      path = '/etc/firewalld/zones/' + zone + '.xml'
##      if File.exists?(path)
##        file = File.open(path, "r")
##        doc = REXML::Document.new(file,{:ignore_whitespace_nodes => :all})
##        rules = self.create_elements(rich_rules)
##        rules.each_element('//rule') do |rule|
##          rule_found = false
##          doc.each_element('//zone/rule') do |element|
##            if rule.to_s == element.to_s
##               rule_found = true
##            end
##          end
##          if rule_found == false
##            return nil
##          end
##        end
##        return :present
##      end
##      return nil
#
#      if @resource.managed?
#        :present
#      else
#        nil
#      end
#    end
#  end

  #def self.title_patterns
  #  [ [ /^()(.*)\Z/, [ [ :name ], [ :uniqname ] ] ] ]
  #end

  newparam(:name) do
    desc "The name of the zone to add rich rule to"
    #defaultto { [@resource[:rich_rules].merge!({"zone"=>@resource[:zone]}).deep_sort] }
    #defaultto { flat_hash(@resource[:rich_rules]).flatten.flatten.join }
    #def munge(s)
    #  super(s.inspect)
    #end

  end
 
  #newparam(:uniqname, :namevar => true) do
  #  desc "The name of the zone to add rich rule to"
  #  defaultto { @resource[:rich_rules].merge!({"zone"=>@resource[:zone]}).deep_sort }
  #  #defaultto { flat_hash(@resource[:rich_rules]).flatten.flatten.join }
  #  def flat_hash(h,f=[],g={})
  #    return g.update({ f=>h }) unless h.is_a? Hash
  #    h.each { |k,r| flat_hash(r,f+[k],g) }
  #    g
  #  end

  #  #def munge(s)
  #  #  puts "UNIQNAME munge: #{s.inspect}"
  #  #  super(s)
  #  #end

  #  #def retrieve
  #  #  puts resource[:zone]
  #  #end

  #end
  #newparam(:ensure) do
  #  desc "Whether or not this resource is in sync"

  #  defaultto :present

  #  #def retrieve
  #  #  puts "Running ENSURE RETRIEVE #{provider.exists?}"
  #  #  puts "Running ENSURE RETRIEVE #{@resource.managed?}"
  #  #  puts "Running ENSURE RETRIEVE #{provider.rich_rules}"
  #  #  puts "Running ENSURE RETRIEVE #{@resource[:rich_rules]}"
  #  #  provider.exists? ? :present : :absent
  #  #end
  #  #
  #  #newvalue(:present) do
  #  #  if @resource.provider and @resource.provider.respond_to?(:create)
  #  #      @resource.provider.create
  #  #  else
  #  #      @resource.create
  #  #  end
  #  #  nil # return nil so the event is autogenerated
  #  #end

  #  #newvalue(:absent) do
  #  #  if @resource.provider and @resource.provider.respond_to?(:destroy)
  #  #      @resource.provider.destroy
  #  #  else
  #  #      @resource.destroy
  #  #  end
  #  #  nil # return nil so the event is autogenerated
  #  #end
  #end

  newparam(:zone) do
    desc "The name of the zone to add rich rule to"
    #munge do |s|
    #  puts "blah #{s}"
    #  puts "blah #{self.class}\n\n\n\n\n"
    #  puts "blah #{resource.paramclass(:name)}\n\n\n\n\n"
    #end
  end 

  newparam(:rich_rules, :array_matching => :all) do
    desc <<-EOT
      list of rich language rules (firewalld.richlanguage(5))
        You have to specify one (and only one)
        of service, port, protocol, icmp_block, masquerade, forward_port
        and one (and only one) of accept, reject, drop

          family - 'ipv4' or 'ipv6', optional, see Rule in firewalld.richlanguage(5)

          source  => {  optional, see Source in firewalld.richlanguage(5)
            address  => mandatory, string, e.g. '192.168.1.0/24'
            invert   => optional, bool, e.g. true
          }

          destination => { optional, see Destination in firewalld.richlanguage(5)
            address => mandatory, string
            invert  => optional, bool, e.g. true
          }

          service - string, see Service in firewalld.richlanguage(5)

          port => { see Port in firewalld.richlanguage(5)
            portid   => mandatory
            protocol => mandatory
          }

          protocol - string, see Protocol in firewalld.richlanguage(5)

          icmp_block - string, see ICMP-Block in firewalld.richlanguage(5)

          masquerade - bool, see Masquerade in firewalld.richlanguage(5)

          forward_port => { see Forward-Port in firewalld.richlanguage(5)
            portid   => mandatory
            protocol => mandatory
            to_port  => mandatory to specify either to_port or/and to_addr
            to_addr  => mandatory to specify either to_port or/and to_addr
          }

          log => {   see Log in firewalld.richlanguage(5)
            prefix => string, optional
            level  => string, optional
            limit  => string, optional
          }

          audit => {  see Audit in firewalld.richlanguage(5)
            limit => string, optional
          }

          action => {  see Action in firewalld.richlanguage(5)
            action_type => string, mandatory, one of 'accept', 'reject', 'drop'
            reject_type => string, optional, use with 'reject' action_type only
            limit       => string, optional
          }
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
      return true
      #puts "IS:     #{is}\nSHOULD: #{@should}"
      def itos(h)
        h.each { |key, value|
          h[key] = itos(value) if value.is_a?(Hash)
          h[key] = value.to_s if value.is_a?(Integer)
        }
      end
      if is.is_a?(Array) and @should.is_a?(Array)
        @should.each { |should_el| 
          itos(should_el) 
          break unless is.detect { |is_el| is_el == should_el } 
        }
      else
        is == @should
      end
    end
  end

  autorequire(:firewalld_zone) do
    catalog.resources.collect do |r|
      r.name if r.is_a?(Puppet::Type.type(:firewalld_zone)) && r[:name] == self[:zone]
    end.compact
  end

  
  #validate do 
  #  #puts "Validate: #{value}"
  #  puts self[:zone]
  #  true
  #end
end
