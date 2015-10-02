class firewalld::directcall {
  include firewalld::configuration

  file {
  '/etc/firewalld/direct.xml':
    owner   => root,
    group   => root,
    mode    => '0644',
    require => Package['firewalld'],
    notify  => Exec['firewalld::reload'],
  }
}
