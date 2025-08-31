<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::post('register', [AuthController::class, 'register']);
Route::post('login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
  Route::get('profile', [AuthController::class, 'profile']);
  Route::put('profile', [AuthController::class, 'updateProfile']);
  Route::post('logout', [AuthController::class, 'logout']);
  Route::post('logout-all', [AuthController::class, 'logoutAll']);
});
