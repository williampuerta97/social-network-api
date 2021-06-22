<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

/**
* @OA\Info(title="API Usuarios", version="1.0")
*
* @OA\Server(url="http://localhost:8000")
*/

class AuthController extends Controller
{
    /**
     * @OA\Post(
     ** path="/api/register",
     *   tags={"Registro"},
     *   summary="Registro",
     *   operationId="register",
     *
     *   @OA\Parameter(
     *      name="name",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
        * @OA\Parameter(
     *      name="email",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
     *   @OA\Parameter(
     *      name="password",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *          type="string"
     *      )
     *   ),
     *   @OA\Response(
     *      response=200,
     *       description="Success",
     *      @OA\MediaType(
     *           mediaType="application/json",
     *      )
     *   ),
     *   @OA\Response(
     *      response=203,
     *       description="Errores de validación"
     *   ),
     *   
     *)
     **/

    public function register(Request $request)
    {
        $validateData = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ], [], [
            "password" => "Contraseña",
            "name" => "Nombre"
        ]);

        if ($validateData->fails()) {
            return response([
                "errors" => $validateData->getMessageBag(),
            ], 203);
        }

        $inputs = $request->all();

        $user = User::create([
            'name' => $inputs['name'],
            'email' => $inputs['email'],
            'password' => Hash::make($inputs['password']),
        ]);

        //$token = $user->createToken('auth_token')->plainTextToken;

        return response([
            //'access_token' => $token,
            //'token_type' => 'Bearer',
            'user' => $user
        ], 200);
    }

    /**
     * @OA\Post(
     ** path="/api/login",
     *   tags={"Login"},
     *   summary="Login",
     *   operationId="login",
     *
     * @OA\Parameter(
     *      name="email",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *           type="string"
     *      )
     *   ),
     *   @OA\Parameter(
     *      name="password",
     *      in="query",
     *      required=true,
     *      @OA\Schema(
     *          type="string"
     *      )
     *   ),
     *  @OA\Response(
     *      response=200,
     *       description="Retorna el token y el usuario autenticado",
     *   ),
     *   @OA\Response(
     *      response=204,
     *       description="No autorizado",
     *   ),
     *   @OA\Response(
     *      response=404,
     *       description="Usuario no encontrado"
     *   ),
     *   
     *)
     **/


    public function login(Request $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response([
                'message' => 'Credenciales inválidas'
            ], 203);
        }

        $user = User::where('email', $request["email"])->first();

        if (!$user) {
            return response([
                'message' => 'No se ha encontrado al usuario'
            ], 203);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response([
            'access_token' => $token,
            'user' => $user
        ], 200);
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response([
            'message'=> 'Ha cerrado sesión'
        ],200);
    }

    public function getUserInfo(Request $request)
    {
        return $request->user();
    }
}
