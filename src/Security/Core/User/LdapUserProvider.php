<?php


namespace snk\Silex\LdapAuth\Security\Core\User;

use Exception;
use Psr\Log\LoggerInterface;
use Zend\Ldap\Ldap;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\User;

/**
 * Ldap user provider.
 */
class LdapUserProvider implements UserProviderInterface
{
    protected $name;
    protected $ldap;
    protected $logger;
    protected $options;

    /**
     * Create new instance.
     *
     * @param string          $name    The service name.
     * @param Ldap            $ldap    Ldap resource to use.
     * @param LoggerInterface $logger  Optional logger.
     * @param array           $options Configuration options.
     */
    public function __construct($name, Ldap $ldap, LoggerInterface $logger = null, array $options = array())
    {
        $this->name = $name;
        $this->ldap = $ldap;
        $this->logger = $logger;
        $defaults = array(
            // LDAP property used as auth name
            'authName' => 'dn',
            'roles' => array(
                // role => group
            ),
            'groupfilter' => 'memberuid=%s',
            'filter' => 'uid=%s',
            'disabledGroup' =>"cn=com.apple.access_disabled",
            'baseDn' => null,
            'groupDn' => null,
        );
        // two level merging
        $this->options = $defaults;
        foreach ($options as $key => $value) {
            $this->options[$key] = is_array($value) ? array_merge($this->options[$key], $value) : $value;
        }
    }

    /**
     * {inheritDoc}.
     */
    public function loadUserByUsername($username)
    {

        $userData = null;
        try {
            if ($collection = $this->ldap->search(sprintf($this->options['filter'], $username), $this->options['baseDn'])) {
                $userData = $collection->getFirst();
            }
        } catch (Exception $e) {
            $unfe = new UsernameNotFoundException('Ldap search failed', 0, $e);
            $unfe->setUsername($username);
            throw $unfe;
        }

        if (!$userData) {
            throw new UsernameNotFoundException(sprintf('Unknown user: username=%s', $username));
        }

        // add roles to user
        $roles = array();
        $groupConnection = $this->ldap->search(sprintf($this->options['groupfilter'], $username), $this->options['groupDn'],1,array("dn"));
        $groups = $groupConnection->toArray();
        foreach($groups as $k => $group){
            if(array_key_exists($group["dn"], $this->options["roles"])){
                 $roles[] = $this->options["roles"][$group["dn"]];
            }
         }

        // check if user is active
        $accessDisabled = $this->ldap->search($this->options['disabledGroup'], $this->options['groupDn']);
        $deactiveUsers = $accessDisabled->getFirst();
        
        return new User($username, null, array_unique($roles),!in_array($username, $deactiveUsers["memberuid"]));
    }

    /**
     * {inheritDoc}.
     */
    public function refreshUser(UserInterface $user){
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {inheritDoc}.
     */
    public function supportsClass($class){
        return $class === 'Symfony\Component\Security\Core\User\User';
    }
}
