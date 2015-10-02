require 'puppet'
require 'puppetx/firewalld/direct'
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'firewalld'))
require 'rexml/document'
include REXML


Puppet::Type.type(:firewalld_direct).provide :directprovider do
  @doc = "The direct rule config manipulator"

  commands :firewall => 'firewall-cmd'

  include PuppetX::Firewalld::Direct

  class << self

    def instances
      # We do not want any instances in this resource as it's a combiner
      []
    end

    def filename
      '/etc/firewalld/direct.xml'
    end

    # Prefetch xml data.
    def prefetch(resources)
      prov = parse_directfile
      Puppet.debug "firewalld prefetch instance resource: (#{prov.name})"
      resources.each do |res, value|
        value.provider = prov.dup
      end
    end

    def parse_directfile
      if File.exist?(filename)
        begin
          doc = REXML::Document.new File.read(filename)
          chains = []
          rules = []
          passthroughs = []

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
        rescue REXML::ParseException
          Puppet.warning("firewalld_direct, #{filename} had malformed XML, your direct rules may now be out of sync until you manually restart firewalld service")
          blank_file
        end
      else
        blank_file
      end
    end

    def blank_file
      new({
        :name          => 'direct',
        :ensure        => :absent,
        :chains        => nil,
        :rules         => nil,
        :passthroughs  => nil,
      })
    end

  end # End of self class

  def firewalld_direct_classvars
    self.class.firewalld_direct_classvars
  end
  
  def firewalld_direct_classvars=(*args)
    self.class.firewalld_direct_classvars = *args
  end

  def create_helper(property, key, should)
    resource[:name] = key
    resource[property] = should
    process_property(property)
  end

  def create
    Puppet.debug("firewalld_direct, #{filename} had an issue, this is bad, we will recreate it but head the warning")
    chains_val = resource.should_content('chains')
    rules_val = resource.should_content('rules')
    passthroughs_val = resource.should_content('passthroughs')

    run_count = firewalld_direct_classvars[:num_runs] - 1
    create_helper(
                  :chains,
                  chains_val.keys[run_count], 
                  chains_val.values[run_count]
                 )
    create_helper(
                  :rules,
                  rules_val.keys[run_count], 
                  rules_val.values[run_count]
                 )
    create_helper(
                  :passthroughs,
                  passthroughs_val.keys[run_count], 
                  passthroughs_val.values[run_count]
                 )


  end

  def destroy
    # We don't do anything if they mark ensure as absent because we don't want to delete the file and once they manage a 
    # single resource of this type we purge any unmanaged rules(not optional as of current)
  end

  def direct_is_to_s(property)
    if (result = firewalld_direct_classvars[:old][property]).empty?
      ''
    else
      result.join("\n")
    end
  end

  def direct_should_to_s(property)
    if (result = firewalld_direct_classvars[:new][property]).empty?
      ''
    else
      result.join("\n")
    end
  end

  def direct_change_to_s(property)
    res_string = "Firewalld_direct\\#{property}\n"
    results = firewalld_direct_classvars[:old][property] - firewalld_direct_classvars[:new][property]
    # results_from is created to provide us with the ability to tell which resource call likely initiated the change of the resource
    # this is so that we can report it back to the log/user to make debugging easier
    results_from = firewalld_direct_classvars[:new][property] - firewalld_direct_classvars[:old][property]
    already_removed = []
    firewalld_direct_classvars[:resources].each do |key,value| 
      # This provides the resource that most likely initiated the removal of the resource
      changed_item = results_from & value[property]
      unless changed_item.empty?
        res_string << "Firewalld_direct[#{key}] prompted addition of \n#{changed_item.join("\n")}\n"
      end
      if (not results.empty?) && (not already_removed.include?(results))
        # This means something was removed and we haven't already mentioned it 
        # In this scenario we have no way of telling which resource instance the removal came from but that's probably ok
        res_string << "Firewalld_direct prompted removal of \n#{results.join("\n")}\n"
        already_removed << results
      end
    end
    res_string
  end

  def remove_items(property, tag, *args)
    # This compares our old hashes from the file against what is being provided in the catalog
    if firewalld_direct_classvars[:new][property] != firewalld_direct_classvars[:old][property]
      # Here we prepare our results of items to remove from property(rules,chains, etc.)
      if !(results = firewalld_direct_classvars[:old][property] - firewalld_direct_classvars[:new][property]).empty?
        # We have to run this rule removal because currently in firewall-cmd --version =~ /0.3.9/ a --reload doesn't remove rules
        results.each do |res|
          # We run the rule removal unless for some reason we have a nil value found in the direct.xml attributes
          # In that case the rule cannot exist in IPTables and the preceding file write and `firewall-cmd --reload` will take care of it
          args_to_run = *args.map { |x| "#{res[x]}" }
          exec_firewall('--direct',"--remove-#{tag}", args_to_run) unless args_to_run.include?("")
        end
      end
      # We return true even if results doesn't find anything to remove, the fact that we ended up in this IF is because
      # obviously something was modified that caused this property to notice an inconsistency in the file.
      # Returning true will ensure that we write the direct file out.
      return true
    end
    # No differences for property found, return false to ensure this property doesn't trigger a file write.
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
    # This method will just build up the hashes until last run of this resource type is complete
    # Once last run is complete it fires off the change, if there is any, so that flush gets called
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
      r_bool = remove_rules if firewalld_direct_classvars[:old][:rules]
      p_bool = remove_passthroughs if firewalld_direct_classvars[:old][:passthroughs]
      # Chains have to be removed last
      c_bool = remove_chains if firewalld_direct_classvars[:old][:chains]
      write_directfile
    end
  end

  def write_directfile
    Puppet.debug "firewalld directfile provider: write_directfile (#{@resource[:name]})"

    # Throw alert (non-run breaking) that the direct.xml file was missing and rules may be inconsistent
    # The direct.xml file should never be missing and this causes us to be unable to check what has changed
    alert("#{filename} was missing and shouldn't have been!\nWe suggest looking for system issues or compromises. 
          We have recreated the file and ran a `firewall-cmd --reload` but in certain versions of 
          firewalld that does not fully reload purge/add direct rules, we suggest manually running service 
          restart of firewalld, this will likely drop current connections") unless File.exist?(filename)

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

  def exists?
    prepare_resources
    # We only check to see if the file doesn't exist, not if they want it to go away using :absent themselves
    @property_hash[:ensure] != :absent
  end

  def filename
    self.class.filename
  end

  def run_increment
    firewalld_direct_classvars[:num_runs] += 1
    firewalld_direct_classvars[:resources][resource[:name].to_sym] = {} unless firewalld_direct_classvars[:resources][resource[:name].to_sym]
  end

  def prepare_resources
    # This method builds our classvar full of the IS values from our prefetch file and records total resources of its type on first call
    # On subsequent calls it just increments the counter so that our later methods will know when to actually fire off their actions
    if firewalld_direct_classvars[:num_direct_resources] == 0
      firewalld_direct_classvars[:old][:chains] = @property_hash[:chains]
      firewalld_direct_classvars[:old][:rules] = @property_hash[:rules]
      firewalld_direct_classvars[:old][:passthroughs] = @property_hash[:passthroughs]
      firewalld_direct_classvars[:num_direct_resources] = 
        resource.catalog.resources.find_all { |x| 
          x.is_a?(Puppet::Type.type(:firewalld_direct)) 
        }.count
    end
    run_increment
  end

end
