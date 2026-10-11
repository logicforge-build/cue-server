/**
 * # registerPushToken.ts
 *
 * Writes a device's FCM token to Firestore on the client's behalf via plain HTTPS, instead of the
 * client Firestore SDK writing directly. Added after confirming (via device testing) that the
 * app's client-side setDoc() call hangs indefinitely on the test device regardless of network —
 * two different WiFi networks and a mobile hotspot all failed identically — while plain HTTPS
 * calls (RevenueCat's own SDK) kept succeeding throughout the same sessions. Routing through this
 * Admin-SDK write sidesteps whatever is blocking the client's gRPC/HTTP2 streaming connection
 * specifically, since it's a completely different code path. The original client-side write is
 * kept commented out in pushNotificationBridge.ts in case this needs revisiting.
 *
 * No request.auth-based scoping (same as the Firestore rule this replaces) — this app has no
 * login, so there's nothing to check the caller's identity against; worst case of a malicious
 * write here is redirecting a push notification target, not exposing sensitive data.
 */

import { onRequest } from 'firebase-functions/v2/https';
import * as logger from 'firebase-functions/logger';
import { getFirestore } from 'firebase-admin/firestore';

export const registerPushToken = onRequest(
  { region: 'us-central1', invoker: 'public' },
  async (req, res) => {
    if (req.method !== 'POST') {
      res.status(405).send('Method not allowed');
      return;
    }

    const { appUserId, fcmToken } = (req.body ?? {}) as { appUserId?: unknown; fcmToken?: unknown };
    if (typeof appUserId !== 'string' || !appUserId || typeof fcmToken !== 'string' || !fcmToken) {
      logger.warn('[registerPushToken] Rejected: missing/invalid appUserId or fcmToken.', { body: req.body });
      res.status(400).send('Missing or invalid appUserId/fcmToken');
      return;
    }

    try {
      await getFirestore().collection('pushTokens').doc(appUserId).set({
        fcmToken,
        updatedAt: Date.now(),
      });
      logger.info(`[registerPushToken] Stored token for app_user_id=${appUserId}`);
      res.status(200).send('OK');
    } catch (error: any) {
      logger.error('[registerPushToken] Write failed.', error);
      res.status(500).send('Write failed');
    }
  }
);
