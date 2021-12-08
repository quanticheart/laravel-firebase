// noinspection JSAccessibilityCheck

/**
 * <a href="https://firebase.google.com/docs/web/setup#available-libraries">Docs</a>
 */
import {initializeApp} from "firebase/app";
import {getAnalytics, logEvent, setUserProperties} from "firebase/analytics";
import {getRemoteConfig} from "firebase/remote-config";
import {getValue} from "firebase/remote-config";
import {fetchAndActivate, ensureInitialized} from "firebase/remote-config";

/**
 * Your web app's Firebase configuration
 * For Firebase JS SDK v7.20.0 and later, measurementId is optional
 * @type {{storageBucket: string, apiKey, messagingSenderId, appId, projectId, measurementId: string, databaseURL: string, authDomain: string}}
 */
const firebaseConfig = {
    apiKey: process.env.FBA_API_KEY,
    authDomain: process.env.FBA_AUTH_DOMAIN + ".firebaseapp.com",
    databaseURL: "https://" + process.env.FBA_AUTH_DOMAIN + ".firebaseio.com",
    projectId: process.env.FBA_AUTH_DOMAIN,
    storageBucket: process.env.FBA_AUTH_DOMAIN + ".appspot.com",
    messagingSenderId: process.env.FBA_SENDER_ID,
    appId: process.env.FBA_APP_ID,
    measurementId: "G-" + process.env.FBA_MEASUREMENT_ID
};

// const firebaseConfig = {
//     apiKey: "AIzaSyDZsuE6WvTLHZJT4E39oXAqXymffEYNdL4",
//     authDomain: "fir-default-163f9.firebaseapp.com",
//     databaseURL: "https://fir-default-163f9.firebaseio.com",
//     projectId: "fir-default-163f9",
//     storageBucket: "fir-default-163f9.appspot.com",
//     messagingSenderId: "688464559028",
//     appId: "1:688464559028:web:0bab6b4f089a315907d0e1",
//     measurementId: "G-20TMDV0JHP"
// };

/**
 * Initialize Firebase
 * @type {FirebaseApp}
 */
const app = initializeApp(firebaseConfig);

/**
 * Initialize Remote Config
 * @type {RemoteConfig}
 */
const rc = getRemoteConfig();
rc.settings.minimumFetchIntervalMillis = 0;
rc.defaultConfig = {
    "Web": {banner: false, color: '#ffce63', pagamento: true}
};

ensureInitialized(rc)
    .then(() => {
        console.log('Firebase Remote Config is initialized');
        window.rcWeb = getValue(rc, "Web");
    })
    .catch((err) => {
        console.log("Firebase Remote Config FAIL = " + err)
    });

window.remoteConfig = (function (myCallback) {
    fetchAndActivate(rc)
        .then(() => {
            let rcWeb = getValue(rc, "Web");
            myCallback(JSON.parse(rcWeb._value))
        })
        .catch((err) => {
            console.log("Firebase Remote Config FAIL = " + err)
        });
});

/**
 * Initialize Remote Config
 * @type {Analytics}
 */
const analytics = getAnalytics(app);

window.sendEvent = (function (eventName, eventParams) {
    if (eventParams != null) {
        logEvent(analytics, eventName, eventParams);
    } else {
        logEvent(analytics, eventName);
    }
});

window.userProperties = (function (id) {
    setUserProperties(analytics, id)
});
