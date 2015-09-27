require 'puppet'
require 'pry'
require 'puppetx/firewalld/direct'
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'firewalld'))
require 'rexml/document'
include REXML


Puppet::Type.type(:firewalld_direct).provide :directprovider do
  @doc = "The direct rule config manipulator"

  commands :firewall => 'firewall-cmd'
  commands :iptables => 'iptables'

  attr_accessor :destroy_zone

  include PuppetX::Firewalld::Direct

  def firewalld_direct_classvars
    self.class.firewalld_direct_classvars
  end
  
  def firewalld_direct_classvars=(*args)
    self.class.firewalld_direct_classvars = *args
  end

  def create
    # This should never run since we always return true in exists?.
    Puppet.debug('firewalld_direct, why are we running create???')
    send("chains=", resource.should_content('chains'))
    send("rules=", resource.should_content('rules'))
    send("passthroughs=", resource.should_content('passthroughs'))
  end

  def destroy
    # This will never run
  end

  def remove_items(property, tag, *args)
    puts "REMOVE #{tag}"
    if firewalld_direct_classvars[:new][property] != firewalld_direct_classvars[:old][property]
      results = firewalld_direct_classvars[:old][property] - firewalld_direct_classvars[:new][property]
      results_from = firewalld_direct_classvars[:new][property] - firewalld_direct_classvars[:old][property]
      puts "#{tag} #{results}"
      firewalld_direct_classvars[:resources].each do |key,value| 
        puts "Firewalld_direct[#{key}] prompted removal of #{results}" unless (results_from & value[property]).empty?
      end
      results_found = firewalld_direct_classvars[:resources].values.map do |res|
        res.name if res[property].include?(results)
      end
      results.each do |res|
        exec_firewall('--direct',"--remove-#{tag}", *args.map { |x| "#{res[x]}" })
      end
      return true
    end
    return false
  end

  def remove_chains
    remove_items(:chains, 'chain', 'ipv', 'table', 'chain')
  end

  def remove_rules
    remove_items(:rules, 'rule', 'ipv', 'table', 'chain', 'priority', 'args')
  end

  def remove_passthroughs
    remove_items(:passthroughs, 'passthrough', 'ipv', 'args')
  end

  def chains
    puts "CHAINS GETTER #{firewalld_direct_classvars[:old][:chains]} - #{firewalld_direct_classvars[:new][:chains]}"
    puts "CHAINS GETTER Run: #{firewalld_direct_classvars[:num_runs]} Total: #{firewalld_direct_classvars[:num_direct_resources]}"
    process_property(:chains)
  end

  def chains=(*)
    # Everything is done in the getter method
  end

  def rules
    process_property(:rules)
  end

  def rules=(*)
    # Everything is done in the getter method
  end

  def passthroughs
    process_property(:passthroughs)
  end

  def passthroughs=(*)
    # Everything is done in the getter method
  end

  def process_property(property)
    firewalld_direct_classvars[:resources][resource[:name].to_sym].merge!({ property => resource[property] })
    firewalld_direct_classvars[:new][property] << resource[property]
    if firewalld_direct_classvars[:num_runs] == firewalld_direct_classvars[:num_direct_resources]
      if firewalld_direct_classvars[:new][property] != firewalld_direct_classvars[:old][property]
        firewalld_direct_classvars[:new][property].flatten!.uniq!
        @property_hash[property] = firewalld_direct_classvars[:old][property]
        resource[property] = firewalld_direct_classvars[:new][property]
        return @property_hash[property]
      end
    end
    return resource[property]
  end

  def flush
    Puppet.debug "firewalld directfile provider: flushing (#{@resource[:name]})"
    # We do not allow flushing until all resources of this type have been processed
    # This is because we're writing to a single file and need to know the state the whole time
    if firewalld_direct_classvars[:num_runs] == firewalld_direct_classvars[:num_direct_resources]
      r_bool = remove_rules
      p_bool = remove_passthroughs
      # Chains have to be removed last
      c_bool = remove_chains
      write_directfile if c_bool or r_bool or p_bool
    end
  end

  def write_directfile
    Puppet.debug "firewalld directfile provider: write_directfile (#{@resource[:name]})"
    doc = REXML::Document.new
    zone = doc.add_element 'direct'
    doc << REXML::XMLDecl.new(version='1.0',encoding='utf-8')

    if not firewalld_direct_classvars[:new][:chains].empty?
      firewalld_direct_classvars[:new][:chains].each do |chain|
        chn = zone.add_element 'chain'
        chn.add_attribute('ipv', chain['ipv'])
        chn.add_attribute('table', chain['table'])
        chn.add_attribute('chain', chain['chain'])
      end
    end

    if not firewalld_direct_classvars[:new][:rules].empty?
      firewalld_direct_classvars[:new][:rules].each do |rule|
        rle = zone.add_element 'rule'
        rle.add_attribute('ipv', rule['ipv'])
        rle.add_attribute('table', rule['table'])
        rle.add_attribute('chain', rule['chain'])
        rle.add_attribute('priority', rule['priority'])
        rle.text = rule['args']
      end
    end

    if not firewalld_direct_classvars[:new][:passthroughs].empty?
      firewalld_direct_classvars[:new][:passthroughs].each do |passthrough|
        pas = zone.add_element 'passthrough'
        pas.add_attribute('ipv', passthrough['ipv'])
        pas.text = rule['args']
      end
    end

    file = File.open(filename, "w+")
    fmt = REXML::Formatters::Pretty.new
    fmt.compact = true
    fmt.write(doc, file)
    file.close
    Puppet.debug "firewalld directfile provider: Changes to #{filename} configuration saved to disk."
    #Reload is now done from a notify command in the puppet code
  end

  # Use example: exec_firewall('--permanent', '--zone', zonevar, '--remove-interface', interfacevar)
  def exec_firewall(*extra_args)
    args=[]
    args << extra_args
    args.flatten!.map! { |x| x.split(' ') }.flatten!
    firewall(args)
  end

  def self.instances
    # We do not want any instances in this resource as it's a combiner
    []
  end

  def exists?
    puts "EXISTS: #{@property_hash[:name]} / #{@resource[:name]}"
    prepare_resources
    #@property_hash[:ensure] == :present || false
    true
  end

  def self.filename
    '/etc/firewalld/direct.xml'
  end

  def filename
    self.class.filename
  end

  # Prefetch xml data.
  # This prefetch is special to zonefile as it does consistency checking
  def self.prefetch(resources)
    Puppet.debug "firewalld prefetch instance: #{instances}"
    prov = parse_directfile
    puts "PROV: #{prov}"
    puts "PROV: #{prov.inspect}"
    #@property_hash = prov
    #parse_directfile.each do |prov|
    Puppet.debug "firewalld prefetch instance resource: (#{prov.name})"
    Puppet.debug "firewalld prefetch instance resource: (#{resources[prov.name]})"
    Puppet.debug "firewalld prefetch instance resource: (#{resources.keys})"
    #prepare_resources
    #if resource = resources[prov.name]
    resources.each do |res, value|
      value.provider = prov.dup
    end
    #if resource = resources[prov.name]
    #  resource.provider = prov
    #  prepare_resources
    #  # Checking for consistency here so it's not called during `puppet resource` rather only on puppet runs
    #  #unless prov.consistent?
    #  #  Puppet.warning("Found IPTables is not consistent with firewalld's zones, we will reload firewalld to attempt to restore consistency.  If this doesn't fix it, you must have a bad zone XML")
    #  #  firewall('--reload')
    #  #  unless prov.consistent?
    #  #    raise Puppet::Error("Bad zone XML found, check your zone configuration")
    #  #  end
    #  #end
    #end
  end

  def prepare_resources
    puts "Prefetch #{firewalld_direct_classvars}"
    puts "Prefetch #{@property_hash[:chains]}"
    firewalld_direct_classvars[:num_runs] += 1
    if firewalld_direct_classvars[:num_direct_resources] == 0
      firewalld_direct_classvars[:old][:chains] = @property_hash[:chains]
      firewalld_direct_classvars[:old][:rules] = @property_hash[:rules]
      firewalld_direct_classvars[:old][:passthroughs] = @property_hash[:passthroughs]
      firewalld_direct_classvars[:num_direct_resources] = 
        resource.catalog.resources.find_all { |x| 
          x.is_a?(Puppet::Type.type(:firewalld_direct)) 
        }.count
    end
    firewalld_direct_classvars[:resources][resource[:name].to_sym] = {} unless firewalld_direct_classvars[:resources][resource[:name].to_sym]
    puts "Prefetch #{firewalld_direct_classvars}"
  end

  def consistent?
    iptables_allow = []
    iptables_deny = []
    firewallcmd_accept = []
    firewallcmd_deny = []
    begin
      iptables_allow = iptables('-L', "IN_#{@resource[:name]}_allow", '-n').split("\n")
      iptables_allow.delete_if { |val| ! val.start_with?("ACCEPT") }
    rescue
    end

    begin
      iptables_deny = iptables('-L', "IN_#{@resource[:name]}_deny", '-n').split("\n")
      iptables_deny.delete_if { |val| ! val.start_with?("DROP", "REJECT") }
    rescue
    end

    begin
      firewallcmd = firewall("--zone=#{@resource[:name]}", '--list-all').split("\n")
      firewallcmd.select! { |val| /\srule family/ =~ val }
      firewallcmd_exp = firewallcmd.map do |val| 
        arr = []
        if /service name=\"(.*?)\"/ =~ val 
          if service_ports = read_service_ports($1)
            service_ports.each do |port|
              arr << val.sub(/(service name=\".*?\")/, "\\1 port=#{port}")
            end
          end
        end
        arr.empty? ? val : arr
      end

      firewallcmd_exp.flatten!

      firewallcmd_accept = firewallcmd_exp.select { |val| /accept\Z/ =~ val }
      firewallcmd_deny = firewallcmd_exp.select { |val| /reject\Z|drop\Z/ =~ val }
    rescue
    end


    unless iptables_allow.count == firewallcmd_accept.count && iptables_deny.count == firewallcmd_deny.count
      Puppet.debug("Consistency issue between iptables and firewalld zone #{@property_hash[:name]}:\niptables_allow.count: #{iptables_allow.count}\nfirewallcmd_accept.count: #{firewallcmd_accept.count}\niptables_deny.count: #{iptables_deny.count}\nfirewallcmd_deny.count: #{firewallcmd_deny.count}")
    end

    # Technically the IPTables allow list and the firewallcmd_accept list(as well as deny lists) numbering lines up 
    # and we could do a regex comparison to verify that the EXACT values existed if we wanted to iptables_allow[index] =~ /...firewallcmd_accept[index].../ for example
    iptables_allow.count == firewallcmd_accept.count && iptables_deny.count == firewallcmd_deny.count
  end
  
  def read_service_ports(service_name)
    file = if File.exist?("/etc/firewalld/services/#{service_name}.xml")
             File.open("/etc/firewalld/services/#{service_name}.xml")
           elsif File.exist?("/usr/lib/firewalld/services/#{service_name}.xml") 
             File.open("/usr/lib/firewalld/services/#{service_name}.xml")
           end
    return false unless file
    doc = REXML::Document.new(file)
    ports = []
    doc.root.elements.each("port") do |ele| 
      ports << "#{ele.attributes["port"]}/#{ele.attributes["protocol"]}" 
    end
    file.close 
    ports
  end

  def self.parse_directfile
    debug "[instances]"

    doc = REXML::Document.new File.read(filename)
    chains = []
    rules = []
    passthroughs = []

    # Set zone level variables
    root = doc.root
    # Go to next file if there is not a doc.root
    #if ! root
    #  next
    #end

    # Loop through the zone elements
    doc.elements.each("direct/*") do |e|

      if e.name == 'chain'
        chains << {
          'ipv' => e.attributes["ipv"].nil? ? nil : e.attributes["ipv"],
          'table' => e.attributes["table"].nil? ? nil : e.attributes["table"],
          'chain' => e.attributes["chain"].nil? ? nil : e.attributes["chain"],
        }
      end
      if e.name == 'rule'
        rules << {
          'ipv' => e.attributes["ipv"].nil? ? nil : e.attributes['ipv'],
          'table' => e.attributes["table"].nil? ? nil : e.attributes["table"],
          'chain' => e.attributes["chain"].nil? ? nil : e.attributes["chain"],
          'priority' => e.attributes["priority"].nil? ? nil : e.attributes["priority"],
          'args' => e.text.nil? ? nil : e.text,
        }
      end
      if e.name == 'passthrough'
        passthroughs << {
          'ipv' => e.attributes["ipv"].nil? ? nil : e.attributes['ipv'],
          'args' => e.elements[0].nil? ? nil : e.elements[0],
        }
      end

    end

    new({
      :name          => 'direct',
      :ensure        => :present,
      :chains        => chains.nil? ? nil : chains,
      :rules         => rules.nil? ? nil : rules,
      :passthroughs  => passthroughs.nil? ? nil : passthroughs,
    })
  end

end
