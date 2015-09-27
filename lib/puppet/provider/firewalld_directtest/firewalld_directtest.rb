module Puppet::Provider::Firewalld_directfile
  def exists?
    #resource.stat ? true : false
    true
  end

  def create
    Puppet.debug('firewalld_directfile, why are we running create???')
    puts 'firewalld_directfile, why are we running create???'
    send("chains=", resource.should_content('chains'))
    send("rules=", resource.should_content('rules'))
    send("passthroughs=", resource.should_content('passthroughs'))
    #resource.property_fix
  end

  def destroy
    #File.unlink(resource[:path]) if exists?
    Puppet.debug('firewalld_directfile, why are we running destroy???')
    puts 'firewalld_directfile, why are we running destroy???'
  end

  def self.filename
    'etc/firewalld/direct.xml'
  end

  def filename
    'etc/firewalld/direct.xml'
  end

  def chains
    puts "CHAINS GETTER #{@property_hash[:chains]} - #{resource.should_content('chains')}"
    #(@property_hash[:chains] == resource.should_content('chains')) ? resource.no_content : actual
    resource.should_content('chains')
    #(@property_hash[:chains] == resource.should_content('chains')) ? @property_hash[:chains] : resource.should_content('chains')
    @property_hash[:chains]
  end

  def chains=(*)
    should = resource.should_content('chains').flatten
    puts "CHAINS SETTER #{@property_hash[:chains]} - #{should}"
    if @property_hash[:chains]
      results = @property_hash[:chains] - should 
      puts "chains #{results}"
      results.each do |res|
        exec_firewall('--direct','--remove-chain',"#{res['ipv']}","#{res['table']}","#{res['chain']}")
      end
    end
    @property_hash[:chains] = should 
  end
  def rules
    #(@property_hash[:rules] == resource.should_content('rules')) ? resource.no_content : actual
    resource.should_content('rules')
    @property_hash[:rules]
  end

  def rules=(*)
    should = resource.should_content('rules').flatten
    puts "RULES SETTER #{@property_hash[:rules]} - #{should}"
    if @property_hash[:rules]
      results = @property_hash[:rules] - should 
      puts "rules #{results}"
      results.each do |res|
        exec_firewall('--direct','--remove-rule',"#{res['ipv']}","#{res['table']}","#{res['chain']}","#{res['priority']}","#{res['args']}")
      end
    end
    @property_hash[:rules] = resource.should_content('rules')
  end
  def passthroughs
    #(@property_hash[:passthroughs] == resource.should_content('passthroughs')) ? resource.no_content : actual
    resource.should_content('passthroughs')
    @property_hash[:passthroughs]
  end

  def passthroughs=(*)
    should = resource.should_content('passthroughs').flatten
    puts "PASSTHROUGHS SETTER #{@property_hash[:passthroughs]} - #{should}"
    if @property_hash[:passthroughs]
      results = @property_hash[:passthroughs] - should 
      puts "passthroughs #{results}"
      results.each do |res|
        exec_firewall('--direct','--remove-chain',"#{res['ipv']}","#{res['args']}")
      end
    end
    @property_hash[:passthroughs] = resource.should_content('passthroughs')
  end
end
