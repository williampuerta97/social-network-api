<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    public function register(Request $request)
    {
        $validateData = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
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

        $token = $user->createToken('auth_token')->plainTextToken;

        return response([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $user
        ], 200);
    }

    public function login(Request $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response([
                'message' => 'Credenciales inválidas'
            ], 401);
        }

        $user = User::where('email', $request["email"])->first();

        if (!$user) {
            return response([
                'message' => 'No se ha encontrado al usuario'
            ], 404);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response([
            'access_token' => $token,
            'token_type' => 'Bearer'
        ]);
    }

    public function logout(Request $request)
    {
        return $request->user()->tokens()->delete();
    }

    public function getUserInfo(Request $request)
    {
        return $request->user();
    }
}
