<?php

namespace rock\access;


interface AccessErrorInterface
{
    const E_VERBS = 1;
    const E_IPS = 2;
    const E_USERS = 4;
    const E_ROLES = 8;
    const E_CUSTOM = 16;

    /**
     * Is http-method error.
     * @return boolean
     */
    public function isErrorVerbs();
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