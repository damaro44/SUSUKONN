<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\GroupController;
use App\Http\Controllers\ContributionController;
use App\Http\Controllers\PayoutController;
use App\Http\Controllers\ChatController;
use App\Http\Controllers\CalendarController;
use App\Http\Controllers\NotificationController;
use App\Http\Controllers\SecurityController;
use App\Http\Controllers\DisputeController;
use App\Http\Controllers\AdminController;

/*
|--------------------------------------------------------------------------
| SusuKonnect API v1 Contract Map
|--------------------------------------------------------------------------
| This file mirrors the Node API routes so mobile clients remain backend-agnostic.
*/

Route::prefix('v1')->group(function () {
    Route::get('/health', fn () => response()->json(['data' => ['status' => 'ok']]));

    Route::post('/auth/register', [AuthController::class, 'register']);
    Route::post('/auth/login', [AuthController::class, 'login']);
    Route::post('/auth/mfa/verify', [AuthController::class, 'verifyMfa']);
    Route::post('/auth/biometric-login', [AuthController::class, 'biometricLogin']);

    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/auth/logout', [AuthController::class, 'logout']);
        Route::get('/auth/me', [AuthController::class, 'me']);

        Route::get('/dashboard', [DashboardController::class, 'index']);

        Route::get('/groups', [GroupController::class, 'index']);
        Route::post('/groups', [GroupController::class, 'store']);
        Route::post('/groups/{groupId}/join', [GroupController::class, 'join']);
        Route::post('/groups/{groupId}/join-requests/{userId}/decision', [GroupController::class, 'reviewJoinRequest']);
        Route::post('/groups/{groupId}/remind', [GroupController::class, 'sendReminders']);
        Route::patch('/groups/{groupId}/status', [GroupController::class, 'updateStatus'])->middleware('can:admin');

        Route::get('/contributions', [ContributionController::class, 'index']);
        Route::post('/contributions/{contributionId}/pay', [ContributionController::class, 'pay']);

        Route::get('/payouts', [PayoutController::class, 'index']);
        Route::post('/groups/{groupId}/payouts/request', [PayoutController::class, 'request']);
        Route::post('/groups/{groupId}/votes', [PayoutController::class, 'vote']);
        Route::post('/groups/{groupId}/priority-claims', [PayoutController::class, 'priorityClaim']);
        Route::post('/payouts/{payoutId}/approve', [PayoutController::class, 'approve']);
        Route::post('/payouts/{payoutId}/confirm-recipient', [PayoutController::class, 'confirmRecipient']);
        Route::post('/payouts/{payoutId}/release', [PayoutController::class, 'release']);

        Route::get('/groups/{groupId}/chat', [ChatController::class, 'index']);
        Route::post('/groups/{groupId}/chat', [ChatController::class, 'store']);
        Route::post('/chat/{messageId}/pin', [ChatController::class, 'togglePin']);

        Route::get('/calendar/events', [CalendarController::class, 'index']);

        Route::get('/notifications', [NotificationController::class, 'index']);
        Route::post('/notifications/{notificationId}/read', [NotificationController::class, 'markRead']);
        Route::post('/notifications/read-all', [NotificationController::class, 'markAllRead']);

        Route::post('/me/kyc', [SecurityController::class, 'submitKyc']);
        Route::post('/me/kyc/session', [SecurityController::class, 'createKycSession']);
        Route::patch('/me/security', [SecurityController::class, 'updateSecurity']);
        Route::post('/me/payment-methods', [SecurityController::class, 'addPaymentMethod']);
        Route::delete('/me/payment-methods/{methodId}', [SecurityController::class, 'removePaymentMethod']);
        Route::delete('/me/devices/{deviceId}', [SecurityController::class, 'removeDevice']);

        Route::post('/disputes', [DisputeController::class, 'store']);

        Route::prefix('/admin')->middleware('can:admin')->group(function () {
            Route::get('/overview', [AdminController::class, 'overview']);
            Route::post('/kyc/{userId}/review', [AdminController::class, 'reviewKyc']);
            Route::post('/fraud-flags', [AdminController::class, 'createFraudFlag']);
            Route::post('/disputes/{disputeId}/resolve', [AdminController::class, 'resolveDispute']);
            Route::get('/export', [AdminController::class, 'exportReport']);
            Route::get('/audit', [AdminController::class, 'exportAudit']);
        });
    });
});
