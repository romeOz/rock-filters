<?php

namespace rock\filters;


use rock\core\filters\CORS;
use rock\helpers\Instance;
use rock\request\Request;
use rock\response\Response;

trait CORSTrait
{
    /**
     * @var Request|string|array the current request. If not set, the `request` application component will be used.
     */
    public $request = 'request';

    /**
     * @var array Basic headers handled for the CORS requests.
     */
    public $cors = [
        'Origin' => ['*'],
        'Access-Control-Request-Method' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
        'Access-Control-Request-Headers' => ['*'],
        'Access-Control-Allow-Credentials' => null,
        'Access-Control-Max-Age' => 86400,
        'Access-Control-Expose-Headers' => [],
    ];

    public function init()
    {
        parent::init();
        if (!$this->response instanceof Response) {
            throw new FilterException(FilterException::NOT_INSTALL_RESPONSE);
        }
        $this->request = Instance::ensure($this->request, '\rock\request\Request');
    }


    /**
     * Extract CORS headers from the request.
     * @return array CORS headers to handle
     */
    public function extractHeaders()
    {
        $headers = [];
        $requestHeaders = array_keys($this->cors);
        foreach ($requestHeaders as $headerField) {
            $serverField = $this->headerizeToPhp($headerField);
            $headerData = isset($_SERVER[$serverField]) ? $_SERVER[$serverField] : null;
            if ($headerData !== null) {
                $headers[$headerField] = $headerData;
            }
        }
        return $headers;
    }

    /**
     * For each CORS headers create the specific response.
     *
     * @param Request $request
     * @param array $requestHeaders CORS headers we have detected.
     * @return array CORS headers ready to be sent
     */
    public function prepareHeaders(Request $request, $requestHeaders)
    {
        $responseHeaders = [];
        // handle Origin
        if (isset($requestHeaders['Origin'], $this->cors['Origin'])) {
            if (in_array('*', $this->cors['Origin']) || in_array($requestHeaders['Origin'], $this->cors['Origin'])) {
                $responseHeaders['Access-Control-Allow-Origin'] = $requestHeaders['Origin'];
            }
        }

        $this->prepareAllowHeaders('Headers', $requestHeaders, $responseHeaders);

        if (isset($requestHeaders['Access-Control-Request-Method'])) {
            $responseHeaders['Access-Control-Allow-Methods'] = implode(', ', $this->cors['Access-Control-Request-Method']);
        }
        if (isset($this->cors['Access-Control-Allow-Credentials'])) {
            $responseHeaders['Access-Control-Allow-Credentials'] = $this->cors['Access-Control-Allow-Credentials'] ? 'true' : 'false';
        }
        if (isset($this->cors['Access-Control-Max-Age']) && $request->isOptions()) {
            $responseHeaders['Access-Control-Max-Age'] = $this->cors['Access-Control-Max-Age'];
        }
        if (isset($this->cors['Access-Control-Expose-Headers'])) {
            $responseHeaders['Access-Control-Expose-Headers'] = implode(', ', $this->cors['Access-Control-Expose-Headers']);
        }

        return $responseHeaders;
    }

    /**
     * Handle classic CORS request to avoid duplicate code.
     * @param string $type the kind of headers we would handle.
     * @param array $requestHeaders CORS headers request by client.
     * @param array $responseHeaders CORS response headers sent to the client.
     */
    protected function prepareAllowHeaders($type, $requestHeaders, &$responseHeaders)
    {
        $requestHeaderField = 'Access-Control-Request-' . $type;
        $responseHeaderField = 'Access-Control-Allow-' . $type;

        if (!isset($requestHeaders[$requestHeaderField], $this->cors[$requestHeaderField])) {
            return;
        }
        if (in_array('*', $this->cors[$requestHeaderField])) {
            $responseHeaders[$responseHeaderField] = $this->headerize($requestHeaders[$requestHeaderField]);
        } else {
            $requestedData = preg_split("/[\\s,]+/", $requestHeaders[$requestHeaderField], -1, PREG_SPLIT_NO_EMPTY);
            $acceptedData = array_uintersect($requestedData, $this->cors[$requestHeaderField], 'strcasecmp');
            if (!empty($acceptedData)) {
                $responseHeaders[$responseHeaderField] = implode(', ', $acceptedData);
            }
        }
    }

    /**
     * Adds the CORS headers to the response.
     * @param Response $response
     * @param array CORS headers which have been computed.
     */
    public function addCorsHeaders(Response $response, $headers)
    {
        if (!empty($headers)) {
            $responseHeaders = $response->getHeaders();
            foreach ($headers as $field => $value) {
                $responseHeaders->set($field, $value);
            }
        }
    }

    /**
     * Convert any string (including php headers with HTTP prefix) to header format like:
     *  * X-PINGOTHER -> X-Pingother
     *  * X_PINGOTHER -> X-Pingother
     * @param string $string string to convert
     * @return string the result in "header" format
     */
    protected function headerize($string)
    {
        $headers = preg_split("/[\\s,]+/", $string, -1, PREG_SPLIT_NO_EMPTY);
        $headers = array_map(function ($element) {
            return str_replace(' ', '-', ucwords(strtolower(str_replace(['_', '-'], [' ', ' '], $element))));
        }, $headers);
        return implode(', ', $headers);
    }

    /**
     * Convert any string (including php headers with HTTP prefix) to header format like:
     *  * X-Pingother -> HTTP_X_PINGOTHER
     *  * X PINGOTHER -> HTTP_X_PINGOTHER
     * @param string $string string to convert
     * @return string the result in "php $_SERVER header" format
     */
    protected function headerizeToPhp($string)
    {
        return 'HTTP_' . strtoupper(str_replace([' ', '-'], ['_', '_'], $string));
    }
}