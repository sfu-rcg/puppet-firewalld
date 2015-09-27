define firewalld::direct_rules(
  $chains = [],
  $rules = [],
  $passthroughs = [],
) {
  include firewalld::directcall

  firewalld_directtest { $name:
    chains       => $chains,
    rules        => $rules,
    passthroughs => $passthroughs,
    notify       => Exec['firewalld::reload'],
  }
}

