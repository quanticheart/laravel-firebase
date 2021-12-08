<?php /** @noinspection PhpUndefinedFieldInspection */

namespace App\Http\Controllers\Firebase;

use App\Firebase\Push\PushSender;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UsersNotificationToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Symfony\Component\HttpFoundation\Response;

class PushController extends Controller
{
    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function saveToken(Request $request): JsonResponse
    {
        $user = new UsersNotificationToken();
        $user->user_id = $request->auth;
        $user->token = $request->token;
        $user->save();
        return response()->json('ok', Response::HTTP_OK);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function sendNotificationToUser(Request $request): JsonResponse
    {
        $firebaseToken = User::find($request->auth)->usersNotificationToken;
        return $this->sendPush($request, $firebaseToken);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function sendNotificationToAllUser(Request $request): JsonResponse
    {
        $firebaseToken = UsersNotificationToken::pushTokenList();
        return $this->sendPush($request, $firebaseToken);
    }

    /**
     * @param Request $request
     * @param array $arrayTokens
     * @return JsonResponse
     */
    private function sendPush(Request $request, array $arrayTokens): JsonResponse
    {
        // Number of messages on bulk (2000) exceeds maximum allowed (1000)
        // split array for not exceed limit token for firebase
        $arrSplit = array_chunk($arrayTokens, 500);
        if (count($arrSplit) > 0) {
            foreach ($arrSplit as $array) {
                $arr = PushSender::allUsers(Arr::pluck($array, "token"),
                    $request->title, $request->message, $request->deeplink);
                if (sizeof($arr) > 0) {
                    foreach ($arr as $index) {
                        UsersNotificationToken::find($array[$index]['id'])->delete();
                    }
                }
            }
            return response()->json('send ok', Response::HTTP_OK);
        } else {
            return response()->json('zero registrations in database', Response::HTTP_OK);
        }
    }
}
