define firewalld::direct_rules(
  $chains = [],
  $rules = [],
  $passthroughs = [],
) {
  include firewalld::directcall

  firewalld_direct { $name:
    chains       => $chains,
    rules        => $rules,
    passthroughs => $passthroughs,
    notify       => [ File['/etc/firewalld/direct.xml'], Exec['firewalld::reload'] ],
  }
}

