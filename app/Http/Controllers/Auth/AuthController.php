<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{

    public function register(Request $request)
    {
        $validateData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'name' => $validateData['name'],
            'email' => $validateData['email'],
            'password' => Hash::make($validateData['password']),
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response([
            'access_token' => $token,
            'token_type' => 'Bearer'
        ], 200);
    }

    public function login(Request $request)
    {
        if(!Auth::attempt($request->only('email', 'password'))) {
            return response([
                'message'=> 'Credenciales inválidas'
            ], 401);
        }

        $user = User::where('email', $request["email"])->first();

        if(! $user){
            return response([
                'message'=> 'No se ha encontrado al usuario'
            ], 404);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response([
            'access_token'=>$token,
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
