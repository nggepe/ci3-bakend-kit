<?php

use chriskacerguis\RestServer\RestController;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Dotenv\Dotenv;

class FC_Controller extends RestController
{
  private $privateKey;

  protected $dq;
  function __construct()
  {
    parent::__construct();
    $dotenv = Dotenv::createImmutable(FCPATH);
    $dotenv->load();
    $this->privateKey = $_ENV['PRIVATE_KEY'];
    $this->load->helper("query_db");
    $this->dq = new QueryDBHelper();
    $cors = $_ENV['CORS'];
    if (isset($_SERVER['HTTP_ORIGIN'])) {
      header("Access-Control-Allow-Origin: $cors");
      header("Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS");
      header("Access-Control-Allow-Headers: Origin, Authorization, X-Requested-With, Content-Type, Accept, jwt");
      header('Access-Control-Allow-Credentials: true');
      header('Access-Control-Max-Age: 86400');    // cache for 1 day
    }
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {

      if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
        // may also be using PUT, PATCH, HEAD etc
        header("Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS");

      if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
        header("Access-Control-Allow-Headers: Origin, Authorization, X-Requested-With, Content-Type, Accept, jwt");

      exit(0);
    }
  }

  function _encrypMyPassword($text)
  {
    return sha1(md5($text));
  }

  public function payloadCheck($data, array $keys): bool
  {
    for ($i = 0; $i < count($keys); $i++) {
      if (!isset($data[$keys[$i]])) return false;
    }
    return true;
  }

  public function res(int $code, $message, $type = "JSON")
  {
    http_response_code($code);
    if ($type === "JSON") {
      echo json_encode($message);
      exit();
    } else {
      echo $message;
    }
  }

  public function jwt_encode($payload)
  {
    $jwt = JWT::encode($payload, $this->privateKey, 'HS256');
    return $jwt;
  }

  public function jwt_decode($jwt)
  {
    try {
      $payload = JWT::decode($jwt, new Key($this->privateKey, "HS256"));
      return $payload;
    } catch (\Throwable $th) {
      return false;
    }
  }
}


class FC_Auth extends FC_Controller
{
  public $user_id;
  function __construct()
  {
    parent::__construct();
    $this->auth_check();
  }

  private function auth_check()
  {
    $jwt = $this->head("jwt");
    if ($jwt == null) {
      $this->response("Bad request!", 400);
      die;
    }

    $payload = $this->jwt_decode($jwt);
    if ($payload == false) {
      $this->response("Bad request!", 400);
      die;
    }

    $this->user_id = $payload;
  }
}
