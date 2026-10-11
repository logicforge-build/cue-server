/**
 * # revenueCatWebhook.ts
 *
 * Receives RevenueCat's webhook, and for a genuine subscription-expiry event, looks up the
 * corresponding device's FCM token (written by the app to Firestore, keyed by whichever App User
 * ID was current at write time — confirmed against RC's own webhook docs that push tokens are
 * never included in the webhook payload itself, regardless of Purchases.setPushToken()) and sends
 * a visible push with default text that the phone rewrites with the user's own numbers (see
 * buildExpiryMessage), so the notification still shows
 * even if the app has been force-quit — confirmed via testing that a purely silent
 * (content-available-only) push is never delivered to a force-quit iOS app at all, while a visible
 * alert push still is. Looks up app_user_id, original_app_user_id, and aliases (RC's own documented
 * recommendation) since RC can merge/alias anonymous IDs across resubscriptions with the same
 * underlying store purchase — confirmed via real device testing, not just docs.
 *
 * Platform payload shapes are deliberately different, not just styled differently — confirmed via
 * research, not assumption:
 * - iOS: `alert` + `content-available: 1` together (apns-push-type must be "alert" and
 *   apns-priority "10" for this combination, not "background"/"5" — a mismatch here can cause APNs
 *   to delay or drop the push). iOS displays the alert at the OS level with no app code involved,
 *   and separately (in parallel, only if not force-quit) wakes the app to re-sync state.
 * - Android: deliberately data-only, NO top-level `notification` key. FCM's own docs confirm that
 *   a message with both `notification` and `data` only reaches onMessageReceived() when the user
 *   taps the tray entry while the app is backgrounded — the data payload would NOT be delivered in
 *   parallel the way this feature needs. The app itself (pushNotificationBridge.ts) builds the
 *   visible notification from the title/body carried in `data`, matching iOS's app-owned-content,
 *   OS-or-app-owned-display split.
 */

import { onRequest } from 'firebase-functions/v2/https';
import { defineSecret } from 'firebase-functions/params';
import * as logger from 'firebase-functions/logger';
import { getFirestore } from 'firebase-admin/firestore';
import { getMessaging } from 'firebase-admin/messaging';

const RC_WEBHOOK_SECRET = defineSecret('RC_WEBHOOK_SECRET');

// Only these RC event types mean "access actually lost" — CANCELLATION alone just means
// won't-renew, the subscriber keeps access until period end. EXPIRATION fires when that access is
// genuinely gone. Kept as an explicit allow-list so extending it (e.g. BILLING_ISSUE) later is a
// one-line change, not a re-derivation.
const TRIGGERING_EVENT_TYPES = new Set(['EXPIRATION']);

interface RevenueCatWebhookBody {
  api_version: string;
  event: {
    type: string;
    app_user_id: string;
    original_app_user_id: string;
    aliases: string[];
    id: string;
    event_timestamp_ms: number;
    // TRIAL | INTRO | NORMAL | PROMOTIONAL | PREPAID — confirmed present on EXPIRATION events via
    // RevenueCat's own webhook field docs. Only TRIAL changes the notification's wording here;
    // everything else reads as a paid-subscription ending.
    period_type?: string;
  };
}

/** Default text only. The phone replaces it with the user's own numbers in their language before
 *  it's shown (iOS: the NotificationService extension, via mutable-content; Android: the app builds
 *  the notification itself) — see the app's src/monetization/winBackNotification.ts. This English
 *  text shows only on app builds without that extension. Same lines as the app's fallback copy. */
function buildExpiryMessage(): { title: string; body: string } {
  return {
    title: 'Your Cue Pro has ended',
    body: 'See what Cue did for you, and pick up where you left off.',
  };
}

/**
 * RC's own docs: "When looking up users from the webhook in your systems, make sure to search
 * both the original_app_user_id and the aliases array" — confirmed necessary via real device
 * testing (RC merges anonymous IDs into one customer via its "Transfer to new App User ID"
 * behavior when the same underlying store purchase resubscribes under a new local ID; the webhook
 * can report app_user_id as an older alias while the app's Firestore token write is keyed by
 * whatever the CURRENT/original ID is). Tries app_user_id first (fast path, common case), then
 * original_app_user_id, then each alias — first doc with a token wins.
 */
async function findTokenDoc(
  event: RevenueCatWebhookBody['event']
): Promise<FirebaseFirestore.DocumentSnapshot | null> {
  const candidateIds = [event.app_user_id, event.original_app_user_id, ...(event.aliases ?? [])];
  const seen = new Set<string>();
  for (const id of candidateIds) {
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const doc = await getFirestore().collection('pushTokens').doc(id).get();
    if (doc.data()?.fcmToken) return doc;
  }
  return null;
}

export const revenueCatWebhook = onRequest(
  // invoker: 'public' opens Cloud Run's own IAM layer to unauthenticated callers (RC can't send a
  // Google-issued OIDC token) — a separate check from the RC_WEBHOOK_SECRET Authorization header
  // validated in the handler body below. Confirmed via device testing: without this, Cloud Run
  // rejects every RC webhook delivery with a 401 before the function code ever runs at all.
  { secrets: [RC_WEBHOOK_SECRET], region: 'us-central1', invoker: 'public' },
  async (req, res) => {
    if (req.get('Authorization') !== RC_WEBHOOK_SECRET.value()) {
      logger.warn('[revenueCatWebhook] Rejected: missing/invalid Authorization header.');
      res.status(401).send('Unauthorized');
      return;
    }

    const body = req.body as RevenueCatWebhookBody;
    const event = body?.event;
    if (!event?.app_user_id || !event?.type) {
      logger.warn('[revenueCatWebhook] Rejected: malformed payload.', { body });
      res.status(400).send('Malformed payload');
      return;
    }

    // Logged unconditionally, before the type filter — event.id/event_timestamp_ms is the only way
    // to tell a genuinely new event apart from RC retrying a previously-failed delivery of the same
    // one (both look identical otherwise; this was a real ambiguity during initial testing).
    logger.info(`[revenueCatWebhook] Received event id=${event.id} type=${event.type} app_user_id=${event.app_user_id} event_timestamp_ms=${event.event_timestamp_ms}`);

    if (!TRIGGERING_EVENT_TYPES.has(event.type)) {
      // Not an error — RC sends every event type to the same webhook URL. Acknowledge and skip.
      res.status(200).send('Ignored (non-triggering event type)');
      return;
    }

    const tokenDoc = await findTokenDoc(event);
    const fcmToken = tokenDoc?.data()?.fcmToken as string | undefined;
    if (!tokenDoc || !fcmToken) {
      logger.warn(`[revenueCatWebhook] No push token on file for app_user_id ${event.app_user_id} (original=${event.original_app_user_id}, aliases=${(event.aliases ?? []).join(',')}), event id=${event.id}.`);
      res.status(200).send('No token on file');
      return;
    }

    try {
      const { title, body } = buildExpiryMessage();
      await getMessaging().send({
        token: fcmToken,
        // Data-only at the top level (no `notification` key) — Android's own visible notification
        // is built by the app from these same title/body fields, see this file's header comment
        // for why (a `notification` key here would stop the data payload reaching the app in
        // parallel while backgrounded).
        data: { type: 'subscription_status_check', title, body },
        android: { priority: 'high' },
        apns: {
          headers: { 'apns-priority': '10', 'apns-push-type': 'alert' },
          // mutable-content: lets the app's NotificationService extension rewrite the text.
          payload: { aps: { alert: { title, body }, sound: 'default', badge: 1, 'content-available': 1, 'mutable-content': 1 } },
        },
      });
      logger.info(`[revenueCatWebhook] Push sent for app_user_id ${event.app_user_id} (token doc ${tokenDoc.id}), event id=${event.id}.`);
      res.status(200).send('Push sent');
    } catch (error: any) {
      // Stale/uninstalled-app token — self-heal by clearing it so future events don't keep trying
      // a dead token. Any other error: log and still 200 (RC's event was received fine; retrying
      // won't fix a push-send failure on our end).
      if (error?.code === 'messaging/registration-token-not-registered') {
        await tokenDoc.ref.delete();
        logger.info(`[revenueCatWebhook] Cleared stale token for ${event.app_user_id}.`);
      } else {
        logger.error('[revenueCatWebhook] Push send failed.', error);
      }
      res.status(200).send('Handled (push send failed)');
    }
  }
);
