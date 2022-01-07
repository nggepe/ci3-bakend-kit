<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends FC_Controller
{
    function __construct()
    {
        parent::__construct();
    }

    /**hanya contoh */
    function login_post()
    {
        $data = $this->post();

        $payloadCheck = $this->payloadCheck($data, ['username', 'password']);
        if (!$payloadCheck) $this->response("Invalid payload", 400);

        $data = $this->dq->get_where_row("users", [
            "username" => $data['username'],
            "password" => $this->_encrypMyPassword($data['password'])
        ]);

        if ($data) {
            if ($data->is_active == 0) $this->response("Akun anda dinonaktifkan oleh admin! Mungkin karena anda menyalahgunakan aturan!", 402);

            $jwt = $this->jwt_encode($data->id);
            $this->response($jwt, 200);
        } else {
            $this->response("Username / password salah", 401);
        }
    }

    /**
     * hanya contoh penggunaan
     */
    function test_key_get()
    {
        $jwt = $this->head("jwt");
        try {
            $output = $this->jwt_decode($jwt);
            $this->response($output, 200);
        } catch (\Throwable $th) {
            $this->response("auth failed", 500);
        }
    }
}
