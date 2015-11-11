<?php

namespace rock\access;


interface AccessErrorInterface
{
    const E_IPS = 1;
    const E_USERS = 2;
    const E_ROLES = 4;
    const E_CUSTOM = 8;

    /**
     * Is username error.
     * @return boolean
     */
    public function isErrorUsers();
    /**
     * Is RBAC error.
     * @return boolean
     */
    public function isErrorRoles();
    /**
     * Is IPs error.
     * @return boolean
     */
    public function isErrorIps();
    /**
     * Is custom error.
     * @return mixed
     */
    public function isErrorCustom();
    /**
     * Return a errors.
     * @return int
     */
    public function getErrors();
} 