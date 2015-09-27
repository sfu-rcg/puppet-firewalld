class firewalld::directcall {
  include firewalld::configuration

  #firewalld_directfile { 'direct':
  #  notify  => Exec['firewalld::reload'],
  #}

  file {
  '/etc/firewalld/direct.xml':
    #content => template('firewalld/direct.xml.erb'),
    owner   => root,
    group   => root,
    mode    => '0644',
    require => Package['firewalld'],
    notify  => Exec['firewalld::reload'],
  }


}
