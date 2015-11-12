<?php

namespace rock\filters;


use rock\helpers\Instance;
use rock\response\Response;

trait AccessTrait
{
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
        return $this->checkInternal();
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
            $result[] =$this->matchUsers((array)$rule['users']);
        }
        if (isset($rule['ips'])) {
            $result[] = $this->matchIps((array)$rule['ips']);
        }
        if (isset($rule['roles'])) {
            $result[] = $this->matchRole((array)$rule['roles']);
        }
        if (isset($rule['custom'])) {
            $result[] = $this->matchCustom($rule);
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