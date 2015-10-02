# Forward declaration
module PuppetX; end
module PuppetX::Firewalld; end

module PuppetX::Firewalld::Direct

  def self.included(klass)
    klass.extend PuppetX::Firewalld::Direct::ClassMethods
    klass.initvars
  end

  module ClassMethods

    attr_accessor :firewalld_direct_classvars

    def initvars
      super
      @firewalld_direct_classvars = 
        {
          :target_file          => '/etc/firewalld/direct.xml',
          :num_direct_resources => 0,
          :num_runs             => 0,
          :resources            => {},
          :old                  => {
            :chains               => [],
            :rules                => [],
            :passthroughs         => [],
          },
          :new                  => {
            :chains               => [],
            :rules                => [],
            :passthroughs         => [],
          },
        }
    end
  end
end
