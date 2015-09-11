require 'puppet'
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'firewalld'))
require 'rexml/document'
include REXML


Puppet::Type.type(:firewalld_zonefile).provide :zoneprovider, :parent => Puppet::Provider::Firewalld do
  @doc = "The zone config manipulator"

#class Hash
#  def deep_sort
#    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
#  end
#end

  commands :firewall => 'firewall-cmd'
  commands :iptables => 'iptables'

  mk_resource_methods

  def flush
    Puppet.debug "firewalld zonefile provider: flushing (#{@resource[:name]})"
    write_zonefile
  end

  def create
    Puppet.debug "firewalld zonefile provider: create (#{@resource[:name]})"
    write_zonefile
  end

  def write_zonefile
    Puppet.debug "firewalld zonefile provider: write_zonefile (#{@resource[:name]})"
    doc = REXML::Document.new
    zone = doc.add_element 'zone'
    doc << REXML::XMLDecl.new(version='1.0',encoding='utf-8')

    if @resource[:target] && ! @resource[:target].empty?
      zone.add_attribute('target', @resource[:target])
    end

    if @resource[:short]
      short = zone.add_element 'short'
      short.text = @resource[:short]
    end

    if @resource[:description]
      description = zone.add_element 'description'
      description.text = @resource[:description]
    end

    if @resource[:interfaces]
      @resource[:interfaces].each do |interface|
        begin
          zoneofinterface = exec_firewall('--get-zone-of-interface', interface)
          if (zoneofinterface.strip != @resource[:name])
            exec_firewall('--permanent', '--zone',zoneofinterface.strip, '--remove-interface', interface)
            exec_firewall('--zone', @resource[:name], '--change-interface', interface)
          end
        rescue Exception => bang
          #puts bang.message
        end

        iface = zone.add_element 'interface'
        iface.add_attribute('name', interface)
      end
    end

    if @resource[:sources]
      @resource[:sources].each do |source|
        # TODO: firewall-cmd --get-zone-of-source...
        src = zone.add_element 'source'
        src.add_attribute('address', source)
      end
    end

    if @resource[:services]
      @resource[:services].each do |service|
        srv = zone.add_element 'service'
        srv.add_attribute('name', service)
      end
    end

    if @resource[:ports]
      @resource[:ports].each do |port|
        prt = zone.add_element 'port'
        prt.add_attribute('port', port['port'])
        prt.add_attribute('protocol', port['protocol'])
      end
    end

    if @resource[:icmp_blocks]
      @resource[:icmp_blocks].each do |icmp_block|
        iblk = zone.add_element 'icmp-block'
        iblk.add_attribute('name', icmp_block)
      end
    end

    if @resource[:masquerade]
      if @resource[:masquerade].at(0).to_s == 'true'
        zone.add_element 'masquerade'
      end
    end

    if @resource[:forward_ports]
      @resource[:forward_ports].each do |forward_port|
        fw_prt = zone.add_element 'forward-port'
        fw_prt.add_attribute('port', forward_port['port'])
        fw_prt.add_attribute('protocol', forward_port['protocol'])
        if forward_port['to_port']
          fw_prt.add_attribute('to-port', forward_port['to_port'])
        end
        if forward_port['to_addr']
          fw_prt.add_attribute('to-addr', forward_port['to_addr'])
        end
      end
    end

    if @resource[:rich_rules]
      @resource[:rich_rules].flatten.each do |rich_rule|
        rule = zone.add_element 'rule'
        if rich_rule['family']
          rule.add_attribute('family', rich_rule['family'])
        end

        if rich_rule['source']
          source = rule.add_element 'source'
          source.add_attribute('address', rich_rule['source']['address'])
          source.add_attribute('invert', rich_rule['source']['invert'])
        end

        if rich_rule['destination']
          dest = rule.add_element 'destination'
          dest.add_attribute('address', rich_rule['destination']['address'])
          dest.add_attribute('invert', rich_rule['destination']['invert'])
        end

        if rich_rule['service']
          service = rule.add_element 'service'
          service.add_attribute('name', rich_rule['service'])
        end

        if rich_rule['port']
          port = rule.add_element 'port'
          port.add_attribute('port', rich_rule['port']['portid'])
          port.add_attribute('protocol', rich_rule['port']['protocol'])
        end

        if rich_rule['protocol']
          protocol = rule.add_element 'protocol'
          protocol.add_attribute('value', rich_rule['protocol'])
        end

        if rich_rule['icmp_block']
          icmp_block = rule.add_element 'icmp-block'
          icmp_block.add_attribute('name', rich_rule['icmp_block'])
        end

        if rich_rule['masquerade']
          rule.add_element 'masquerade'
        end

        if rich_rule['forward_port']
          fw_port = rule.add_element 'forward-port'
          fw_port.add_attribute('port', rich_rule['forward_port']['portid'])
          fw_port.add_attribute('protocol', rich_rule['forward_port']['protocol'])
          if rich_rule['forward_port']['to_port']
            fw_port.add_attribute('to-port', rich_rule['forward_port']['to_port'])
          end
          if rich_rule['forward_port']['to_addr']
            fw_port.add_attribute('to-addr', rich_rule['forward_port']['to_addr'])
          end
        end

        if rich_rule['log']
          log = rule.add_element 'log'
          if rich_rule['log']['prefix']
            log.add_attribute('prefix', rich_rule['log']['prefix'])
          end
          if rich_rule['log']['level']
            log.add_attribute('level', rich_rule['log']['level'])
          end
          if rich_rule['log']['limit']
            limit = log.add_element 'limit'
            limit.add_attribute('value', rich_rule['log']['limit'])
          end
        end

        if rich_rule['audit']
          audit = rule.add_element 'audit'
          if rich_rule['audit']['limit']
            limit = audit.add_element 'limit'
            limit.add_attribute('value', rich_rule['audit']['limit'])
          end
        end

        if rich_rule['action']
          action = rule.add_element rich_rule['action']['action_type']
          if rich_rule['action']['reject_type']
            action.add_attribute('type', rich_rule['action']['reject_type'])
          end
          if rich_rule['action']['limit']
            limit = action.add_element 'limit'
            limit.add_attribute('value', rich_rule['action']['limit'])
          end
        end
      end
    end

    path = '/etc/firewalld/zones/' + @resource[:name] + '.xml'
    file = File.open(path, "w+")
    fmt = REXML::Formatters::Pretty.new
    fmt.compact = true
    fmt.write(doc, file)
    file.close
    Puppet.debug "firewalld zonefile provider: Changes to #{path} configuration saved to disk."
    #Reload is now done from a notify command in the puppet code
  end

  # Utilized code from crayfishx/puppet-firewalld as the firewall-cmd needs it's arguments properly formatted from this ruby code, and this function does it well, fixes issues that arose from doing firewall('--permanent --zone=foo --remove-interface=lo')
  # So now use exec_firewall('--permanent', '--zone', zonevar, '--remove-interface', interfacevar)
  def exec_firewall(*extra_args)
    args=[]
    args << extra_args
    args.flatten!
    firewall(args)
  end

  def self.instances
    debug "[instances]"
    zonefiles = Dir["/etc/firewalld/zones/*.xml"]

    zone = []

    zonefiles.each do |path|
      zonename = File.basename(path, ".xml")
      doc = REXML::Document.new File.read(path)
      target = ''
      version = ''
      short = ''
      description = ''
      interface = []
      source = []
      service = []
      ports = []
      icmp_blocks = []
      masquerade = false
      forward_ports = []
      rich_rules = []

      # Set zone level variables
      root = doc.root
      # Go to next file if there is not a doc.root
      if ! root
        next
      end
      target = root.attributes["target"]
      version = root.attributes["version"]

      # Loop through the zone elements
      doc.elements.each("zone/*") do |e|

        if e.name == 'short'
          short = e.text.to_s.strip
        end
        if e.name == 'description'
          description = e.text.to_s.strip
        end
        if e.name == 'interface'
          interface << e.attributes["name"]
        end
        if e.name == 'source'
          source << e.attributes["address"]
        end
        if e.name == 'service'
          service << e.attributes["name"]
        end
        if e.name == 'port'
          ports << {
            'port' => e.attributes["port"].nil? ? nil : e.attributes["port"],
            'protocol' => e.attributes["protocol"].nil? ? nil : e.attributes["protocol"],
          }
        end
        if e.name == 'icmp-block'
          icmp_blocks << e.attributes["name"]
        end
        if e.name == 'masquerade'
          masquerade = true
        end
        if e.name == 'forward-port'
          forward_ports << {
            'port' => e.attributes["port"].nil? ? nil : e.attributes['port'],
            'protocol' => e.attributes["protocol"].nil? ? nil : e.attributes["protocol"],
            'to_port' => e.attributes["to-port"].nil? ? nil : e.attributes["to-port"],
            'to_addr' => e.attributes["to-addr"].nil? ? nil : e.attributes["to-addr"],
          }
        end

        if e.name == 'rule'

            rule_source = {}
            rule_destination = {}
            rule_service = ''
            rule_ports = {}
            rule_protocol = ''
            rule_icmp_blocks = ''
            rule_masquerade = false
            rule_forward_ports = {}
            rule_log = {}
            rule_audit = {}
            rule_action = {}
            # Changed rule_family to blank to start as it is an optional variable and should be treated as such for consistency
            rule_family = ''
            
            # family is a rule attribute rather than an element and therefore must happen prior to the elements loop
            rule_family = e.attributes["family"].nil? ? nil : e.attributes["family"]

          e.elements.each do |rule|
            if rule.name == 'source'
              rule_source['address'] = rule.attributes["address"]
              if rule.attributes["invert"] == 'true'
                rule_source['invert'] = true
              else
                rule_source['invert'] = rule.attributes["invert"].nil? ? nil : false
              end
              rule_source.delete_if { |key,value| key == 'invert' and value == nil}

            end
            if rule.name == 'destination'
              rule_destination['address'] = rule.attributes["address"]
              if rule.attributes["invert"] == 'true'
                rule_destination['invert'] = true
              else
                rule_destination['invert'] = rule.attributes["invert"].nil? ? nil : false
              end
              rule_destination.delete_if { |key,value| key == 'invert' and value == nil}
            end
            if rule.name == 'service'
              rule_service = rule.attributes["name"]
            end
            if rule.name == 'port'
              rule_ports['portid'] = rule.attributes["port"].nil? ? nil : rule.attributes["port"]
              rule_ports['protocol'] = rule.attributes["protocol"].nil? ? nil : rule.attributes["protocol"]
            end
            if rule.name == 'protocol'
              rule_protocol = rule.attributes["value"]
            end
            if rule.name == 'icmp-block'
              rule_icmp_blocks = rule.attributes["name"]
            end
            if rule.name == 'masquerade'
              rule_masquerade = true
            end
            if rule.name == 'forward-port'
              rule_forward_ports['portid'] = rule.attributes["port"].nil? ? nil : rule.attributes["port"]
              rule_forward_ports['protocol'] = rule.attributes["protocol"].nil? ? nil : rule.attributes["protocol"]
              rule_forward_ports['to_port'] = rule.attributes["to-port"].nil? ? nil : rule.attributes["to-port"]
              rule_forward_ports['to_addr'] = rule.attributes["to-addr"].nil? ? nil : rule.attributes["to-addr"]
            end
            if rule.name == 'log'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_log['prefix'] = rule.attributes["prefix"].nil? ? nil : rule.attributes["prefix"]
              rule_log['level'] = rule.attributes["level"].nil? ? nil : rule.attributes["level"]
              rule_log['limit'] = limit
            end
            if rule.name == 'audit'
              rule_audit['limit'] = rule.elements["limit"].attributes["value"].nil? ? nil : rule.elements["limit"].attributes["value"]
            end
            if rule.name == 'accept'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_action['action_type'] = rule.name
              rule_action['reject_type'] = nil
              rule_action['limit'] = limit
            end
            if rule.name == 'reject'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_action['action_type'] = rule.name
              rule_action['reject_type'] = rule.attributes["type"].nil? ? nil : rule.attributes["type"]
              rule_action['limit']  = limit
            end
            if rule.name == 'drop'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_action['action_type'] = rule.name
              rule_action['reject_type'] = nil
              rule_action['limit']  = limit
            end
          end
          rich_rules << {
            'source'        => rule_source.empty? ? nil : rule_source,
            'action'        => rule_action.empty? ? nil : rule_action,
            'audit'         => rule_audit.empty? ? nil : rule_audit,
            'destination'   => rule_destination.empty? ? nil : rule_destination,
            'family'        => rule_family.empty? ? nil : rule_family,
            'forward_port'  => rule_forward_ports.empty? ? nil : rule_forward_ports,
            'icmp_block'    => rule_icmp_blocks.empty? ? nil : rule_icmp_blocks,
            'log'           => rule_log.empty? ? nil : rule_log,
            'masquerade'    => rule_masquerade.nil? ? nil : rule_masquerade,
            'port'          => rule_ports.empty? ? nil : rule_ports,
            'protocol'      => rule_protocol.empty? ? nil : rule_protocol,
            'service'       => rule_service.empty? ? nil : rule_service,
          }

        end
        # remove services if not set so the data type matches the data type returned by the puppet resource.
        rich_rules.each do |rr|

          # This will recursively remove any hashes that have nil values
          # We must still specify special items like masquerade because it's false rather than nil
          p = proc do |_, v|
            v.delete_if(&p) if v.respond_to? :delete_if
            v.nil? #|| v.respond_to?(:"empty?") && v.empty?
          end
          rr.delete_if(&p)

          rr.delete_if { |key,value| key == 'masquerade' and value == false}

        end
        # We run a deep hash sort outside of the each block so that it can take direct effect without having to write a new variable
        rich_rules.map! { |rr| rr.deep_sort }
      end

      # convert the masquerade variable from boolean to array so the data type matches the data type returned by the puppet resource.
      if masquerade
        masquerade = ['true']
      else
        masquerade = ['false']
      end

      # Add hash to the zone array
      zone << new({
        :name          => zonename,
        :ensure        => :present,
        :target        => target.nil? ? nil : target,
        :version       => version.nil? ? nil : version,
        :short         => short.nil? ? nil : short,
        :description   => description.nil? ? nil : description,
        :interfaces    => interface.empty? ? nil : interface,
        :sources       => source.empty? ? nil : source,
        :services      => service.empty? ? nil : service,
        :ports         => ports.empty? ? nil : ports,
        :icmp_blocks   => icmp_blocks.empty? ? nil : icmp_blocks,
        :masquerade    => masquerade.nil? ? nil : masquerade,
        :forward_ports => forward_ports.empty? ? nil : forward_ports,
        :rich_rules    => rich_rules.empty? ? nil : rich_rules,
      })

    end
    zone
  end

  def destroy
    path = '/etc/firewalld/zones/' + @resource[:name] + '.xml'
    File.delete(path)
    Puppet.debug "firewalld zonefile provider: removing (#{path})"
    @property_hash.clear
  end

  def exists?
    if resource[:target] == nil
      resource[:target] = ''
    end
    @property_hash[:ensure] == :present || false
  end

  # Prefetch xml data.
  # This prefetch is special to zone as it does consistency checking
  def self.prefetch(resources)
    grabbed_catalog = false
    catalog_res = nil
    debug("[prefetch(resources)]")
    Puppet.debug "firewalld prefetch instance: #{instances}"
    instances.each do |prov|
      Puppet.debug "firewalld prefetch instance resource: (#{prov.name})"
      if resource = resources[prov.name]
        resource.provider = prov
        unless grabbed_catalog
          puts "Have not grabbed catalog yet"
          grabbed_catalog = (catalog_res = resource.catalog) ? true : false
          puts grabbed_catalog
          puts catalog_res
        end

        # Checking for consistency here so it's not called during `puppet resource` rather only on puppet runs
        unless prov.consistent?
          Puppet.debug("Found IPTables is not consistent with firewalld's default zone, we will reload firewalld to attempt to restore consistency.  If this doesn't fix it, you must have a bad zone XML")
          firewall('--reload')
          unless prov.consistent?
            Puppet.fail("Bad zone XML found, check your zone configuration")
          end
        end

      end
    end
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
end
