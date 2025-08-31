<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rule;

class AuthController extends Controller
{
  public function register(Request $request)
  {
    $request->validate([
      'name' => 'required|string|max:255',
      'email' => 'required|email|unique:users,email',
      'password' => 'required|confirmed|min:8'
    ]);

    $user = User::create([
      'name' => $request->name,
      'email' => $request->email,
      'password' => Hash::make($request->password)
    ]);

    return response()->json([
      'success' => true,
      'message' => 'User registered successfully',
      'data' => $user
    ], 201);
  }

  public function login(Request $request)
  {
    $request->validate([
      'email' => 'required|email',
      'password' => 'required'
    ]);

    $user = User::where('email', $request->email)->first();

    if ($user && Hash::check($request->password, $user->password)) {
      // Create token for the authenticated user
      $token = $user->createToken('auth-token');

      return response()->json([
        'success' => true,
        'message' => 'Login successful',
        'data' => [
          'user' => $user,
          'token' => $token->plainTextToken
        ]
      ]);
    }

    return response()->json([
      'success' => false,
      'message' => 'Invalid credentials'
    ], 401);
  }

  public function profile(Request $request)
  {
    return response()->json([
      'success' => true,
      'data' => $request->user()
    ]);
  }

  public function updateProfile(Request $request)
  {
    $user = $request->user();

    $request->validate([
      'name' => 'required|string|max:255',
      'email' => [
        'required',
        'email',
        Rule::unique('users')->ignore($user->id)
      ],
      'password' => 'nullable|confirmed|min:8'
    ]);

    $user->name = $request->name;
    $user->email = $request->email;

    if ($request->filled('password')) {
      $user->password = Hash::make($request->password);
    }

    $user->save();

    return response()->json([
      'success' => true,
      'message' => 'Profile updated successfully',
      'data' => $user
    ]);
  }

  public function logout(Request $request)
  {
    // Delete current access token
    $request->user()->currentAccessToken()->delete();

    return response()->json([
      'success' => true,
      'message' => 'Logged out successfully'
    ]);
  }

  public function logoutAll(Request $request)
  {
    // Delete all user's tokens
    $request->user()->tokens()->delete();

    return response()->json([
      'success' => true,
      'message' => 'Logged out from all devices successfully'
    ]);
  }
}
