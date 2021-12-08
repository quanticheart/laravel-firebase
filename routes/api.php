<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
const folderController = 'App\Http\Controllers\Api\\';
const pushController = folderController . 'Firebase\PushController@';

Route::group(["prefix" => "user"], function () {
    Route::group(["prefix" => "notify"], function () {
        /* push */
        Route::post('/push/all', pushController . 'sendNotificationToAllUser');
        Route::post('/push', pushController . 'sendNotificationToUser');
        Route::post('/push/save-token', pushController . 'saveToken');
    });
});
