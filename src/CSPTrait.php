<?php

namespace rock\filters;


use rock\response\Response;

trait CSPTrait
{

    public $policy = [];

    public function send()
    {
        if (!$this->response instanceof Response) {
            throw new FilterException(FilterException::NOT_INSTALL_RESPONSE);
        }
        $policy = [];
        if (!isset($this->policy['default-src'])) {
            $this->policy['default-src'] = "'self'";
        }
        foreach ($this->policy as $name => $value) {
            if (is_string($value)) {
                $value = str_replace('\'', '', $value);
                $value = preg_replace(['/\b(self|none|unsafe-eval|unsafe-inline)\b/', '/\s+/'], ["'$0'", ' '], $value);
                $policy[] = $name . ' ' . rtrim($value, ';') . ';';
                continue;
            }
            $value = implode(' ', $value);
            $value = str_replace('\'', '', $value);
            $value = preg_replace(['/\b(self|none|unsafe-eval|unsafe-inline)\b/', '/\s+/'], ["'$0'", ' '], $value);
            $policy[] = "{$name} {$value};";
        }

        if ($policy) {
            $policy = implode(' ', $policy);

            /* @link http://caniuse.com/#feat=contentsecuritypolicy
             * Does not conflict IE and Firefox <= 22 @link http://habrahabr.ru/company/yandex/blog/206508/ and @link https://events.yandex.ru/lib/talks/2587/
             */
            if ($this->isIE()) {
                $this->response->getHeaders()->set('X-Content-Security-Policy', $policy); // for IE10 or great (does not Edge)
                return;
            }
            $this->response->getHeaders()->set('Content-Security-Policy', $policy);
        }
    }

    /**
     * Check Internet Explorer (does not Edge).
     * @return bool
     */
    protected function isIE()
    {
        return isset($_SERVER['HTTP_USER_AGENT']) && (strpos($_SERVER['HTTP_USER_AGENT'], 'Trident') !== false || strpos($_SERVER['HTTP_USER_AGENT'], 'MSIE') !== false);
    }
}