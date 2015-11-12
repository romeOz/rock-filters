<?php

namespace rock\filters;


use rock\csrf\CSRF;
use rock\helpers\ArrayHelper;
use rock\helpers\Instance;
use rock\request\Request;
use rock\response\Response;

trait CSRFFilterTrait
{
    /**
     * @var CSRF|string|array the CSRF instance.
     */
    public $csrf = 'csrf';

    /**
     * @throws \rock\helpers\InstanceException
     */
    public function init()
    {
        parent::init();
        $this->csrf = Instance::ensure($this->csrf, '\rock\csrf\CSRF');
        $this->csrf->enableCsrfValidation = $this->validate;
        $this->verbs = (array)$this->verbs;
        if ($this->verbs === ['*']) {
            $this->verbs = ['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS', 'PATH'];
        }
    }

    protected function check()
    {
        if (!$this->validate || !$this->request->isMethods($this->verbs)) {
            return true;
        }
        $this->compare = $this->getCompare();
        if (!$this->csrf->check($this->compare)) {
            if ($this->response instanceof Response) {
                $this->response->setStatusCode(403, 'Invalid CSRF-token.');
            }
            if ($this->throwException === true) {
                throw new FilterException('Invalid CSRF-token.');
            }
            return false;
        }
        return true;
    }

    protected function getCompare()
    {
        if (isset($this->compare)) {
            return $this->compare;
        }

        if ($globals = $this->getGlobalsVars()) {
            if ($global = ArrayHelper::searchByKey($this->csrf->csrfParam, $globals)) {
                return current($global);
            }
        }

        return $this->compare;
    }

    protected function getGlobalsVars()
    {
        if ($this->request->isPost() && in_array('POST', $this->verbs, true)) {
            return $this->request->post();
        }

        if ($this->request->isGet() && in_array('GET', $this->verbs, true)) {
            return $this->request->get();
        }

        if ($this->request->isPut() && in_array('PUT', $this->verbs, true)) {
            return $this->request->post();
        }

        if ($this->request->isDelete() && in_array('DELETE', $this->verbs, true)) {
            return $this->request->post();
        }

        return [];
    }
}