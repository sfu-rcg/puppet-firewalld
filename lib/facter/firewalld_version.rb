# Make firewalld version available as a fact

Facter.add("firewalld_version") do
  confine :kernel => 'Linux'
  setcode do
    if Facter::Util::Resolution.which('firewall-cmd')
      results = Facter::Util::Resolution.exec('firewall-cmd --version').match(/^(\d+\.\d+\.\d+)$/)
      if results
        results[1]
      end
    end
  end
end
