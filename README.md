# Time-bound upload exceptions

This sample Worker supports a default Browser Isolation upload-block policy while allowing authorised administrators to approve temporary exceptions for individual users and domains.

The Worker creates a temporary Gateway HTTP `Do Not Isolate` rule for the approved user/domain/time window, then removes it automatically when the window ends.

## Before you deploy

- Create and test a Gateway HTTP **Isolate** policy that applies to domains outside your approved-domain list, with **File uploads** set to **Do not allow**.
- Note that policy's precedence. The Worker creates exceptions immediately above it, using the first available precedence value below the isolate policy.
- Place the Worker behind a Cloudflare Access application. The Worker requires the Access identity headers to authenticate requesters and approvers.

## Deploy

1. Create a KV namespace:

   ```sh
   wrangler kv namespace create UPLOAD_GRANT_LEDGER
   ```

2. Update `wrangler.jsonc`:

   - Set the KV namespace ID.
   - Set `CF_ACCOUNT_ID`.
   - Set `ISOLATE_RULE_PRECEDENCE` to the precedence of the existing isolation policy.
   - Set `APPROVER_EMAILS` to one or more comma-separated Cloudflare Access identities.

3. Create a least-privilege API token in the target account with **Zero Trust: Edit**. Store it as a Worker secret:

   ```sh
   wrangler secret put CF_API_TOKEN
   ```

4. Optionally configure an alert webhook for submitted requests, retries and reconciliation failures:

   ```sh
   wrangler secret put ALERT_WEBHOOK
   ```

5. Deploy:

   ```sh
   wrangler deploy
   ```

6. Create a Cloudflare Access application for the deployed Worker hostname. Allow authenticated requesters to open the request page and configure the approver identities in `APPROVER_EMAILS`.

## Use

- Request page: `/`
- Approval queue: `/approvals`

The request page accepts a `client_url` query parameter, for example:

```text
/?client_url=https://dropbox.com/home
```

This pre-fills the hostname in the request form. It can be used with a Browser Isolation custom block dialog where that feature is enabled.

## Behaviour

1. A requester submits a domain, duration and optional start time.
2. The request remains `pending`; no Gateway exception is created.
3. An approver selects **Approve** or **Deny** in `/approvals`.
4. On approval, a Durable Object alarm creates the user/domain-specific `Do Not Isolate` rule at the requested start time.
5. The Durable Object deletes the rule at the end time.
6. A two-minute cron reconciliation removes expired or orphaned rules if an alarm does not complete.

## Operational notes

- Users must close and reopen the relevant site after the exception starts or ends so the session receives the updated policy.
- The user’s Access email is used for the Gateway exception. It is not accepted from the form.
- Start times are validated to the current minute. End times must be in the future.
- The one-, two- and five-minute durations are intended for testing. Remove them before production if they do not align with your approval policy.
- Review and test the solution in a non-production account before deployment.
