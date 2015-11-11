<?php

namespace rock\filters;


use rock\helpers\Instance;

trait AccessTrait
{
    /**
     * @var array
     */
    public $rules = [];
    /**
     * Owner object
     *
     * @var object
     */
    public $owner;
    /**
     * Sending response headers. `true` by default.
     * @var bool
     */
    public $sendHeaders = false;
    /**
     * @var int
     */
    protected $errors = 0;
    /** @var  \rock\user\User|string|array */
    public $user = 'user';

    public function init()
    {
        parent::init();
        $this->user = Instance::ensure($this->user, '\rock\user\user', [], false);
    }

    /**
     * Checks a access.
     * @return bool
     */
    public function check()
    {
        if (empty($this->rules) || !is_array($this->rules) || empty($this->owner)) {
            return true;
        }
        if ($valid = $this->checkInternal()) {
            $this->errors = 0;
        }
        return $valid;
    }

    /**
     * Returns a errors.
     * @return int
     */
    public function getErrors()
    {
        return $this->errors;
    }

    public function isErrorVerbs()
    {
        return (bool)(self::E_VERBS & $this->errors);
    }

    public function isErrorUsers()
    {
        return (bool)(self::E_USERS & $this->errors);
    }

    public function isErrorRoles()
    {
        return (bool)(self::E_ROLES & $this->errors);
    }

    public function isErrorIps()
    {
        return (bool)(self::E_IPS & $this->errors);
    }

    public function isErrorCustom()
    {
        return (bool)(self::E_CUSTOM & $this->errors);
    }

    protected function checkInternal()
    {
        if (!isset($this->rules['allow'])) {
            return true;
        }
        if (($valid = $this->matches($this->rules)) === null) {
            return !$this->rules['allow'];
        }

        return (bool)$valid;
    }

    /**
     * Checks a username, role and ip.
     * @param array $rule array data of access
     * @return bool|null
     */
    protected function matches(array $rule)
    {
        $rule['allow'] = (bool)$rule['allow'];
        $result = [];
        if (isset($rule['users'])) {
            $result[] = $this->addError($this->matchUsers((array)$rule['users']), self::E_USERS, $rule['allow']);
        }
        if (isset($rule['ips'])) {
            $result[] = $this->addError($this->matchIps((array)$rule['ips']), self::E_IPS, $rule['allow']);
        }
        if (isset($rule['roles'])) {
            $result[] = $this->addError($this->matchRole((array)$rule['roles']), self::E_ROLES, $rule['allow']);
        }
        if (isset($rule['custom'])) {
            $result[] = $this->addError($this->matchCustom($rule), self::E_CUSTOM, $rule['allow']);
        }
        if (empty($result)) {
            return null;
        }
        if (in_array(false, $result, true)) {
            return null;
        }

        return $rule['allow'];
    }

    /**
     * Checks a username.
     * @param array $users array data of access
     * @return bool
     * @throws FilterException
     */
    protected function matchUsers(array $users)
    {
        if (!$this->user instanceof \rock\user\User) {
            throw new FilterException(FilterException::UNKNOWN_CLASS, ['class' => '\rock\user\User']);
        }
        // All users
        if (in_array('*', $users)) {
            return true;
            // guest
        } elseif (in_array('?', $users) && $this->user->isGuest()) {
            return true;
            // Authenticated
        } elseif (in_array('@', $users) && !$this->user->isGuest()) {
            return true;
            // username
        } elseif (in_array($this->user->get('username'), $users)) {
            return true;
        }
        $this->sendHeaders();
        return false;
    }

    /**
     * Checks a IPs.
     * @param array $ips array data of access
     * @return bool
     */
    protected function matchIps(array $ips)
    {
        // all ips
        if (in_array('*', $ips)) {
            return true;
        }
        $result = $this->request->isIps($ips);
        if (!$result) {
            $this->sendHeaders();
        }
        return $result;
    }

    /**
     * Checks a role (RBAC).
     * @param array $roles
     * @return bool
     * @throws FilterException
     */
    protected function matchRole(array $roles)
    {
        if (!$this->user instanceof \rock\user\User) {
            throw new FilterException(FilterException::UNKNOWN_CLASS, ['class' => '\rock\user\User']);
        }
        // all roles
        if (in_array('*', $roles)) {

            return true;
        } elseif (in_array('?', $roles) && $this->user->isGuest()) {
            return true;
            // Authenticated
        } elseif (in_array('@', $roles) && !$this->user->isGuest()) {
            return true;
        }

        foreach ($roles as $role) {
            if (!$this->user->check($role)) {
                $this->sendHeaders();
                return false;
            }
        }

        return true;
    }

    /**
     * Checks a custom rule.
     * @param array $rule array data of access
     * @return bool
     */
    protected function matchCustom(array $rule)
    {
        $rule['custom'][1] = isset($rule['custom'][1]) ? $rule['custom'][1] : [];
        list($function, $args) = $rule['custom'];

        $result = (bool)call_user_func(
            $function,
            array_merge(['owner' => $this->owner/*, 'action' => $this->action*/], $args)
        );
        if (!$result) {
            $this->sendHeaders();
        }
        return $result;
    }

    /**
     * Adds a error.
     * @param bool $is
     * @param int $error
     * @param bool $allow
     * @return bool
     */
    protected function addError($is, $error, $allow)
    {
        if ($is === false || $allow === false) {
            $this->errors |= $error;
        }

        return $is;
    }

    protected function sendHeaders()
    {
        if (!$this->sendHeaders) {
            return;
        }
        if (!$this->response instanceof Response) {
            throw new FilterException(FilterException::NOT_INSTALL_RESPONSE);
        }
        $this->response->status403();
    }
}