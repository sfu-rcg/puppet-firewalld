# Make firewalld version available as a fact

Facter.add("firewalld_version") do
  confine :kernel => 'Linux'
  setcode 'firewall-cmd --version'
end
