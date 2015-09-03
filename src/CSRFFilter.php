<?php

namespace rock\filters;


use rock\core\filters\ActionFilter;

class CSRFFilter extends ActionFilter
{
    use CSRFTrait;

    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
        return $this->check();
    }
}