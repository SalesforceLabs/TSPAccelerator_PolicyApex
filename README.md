# TSP Accelerator — Policy Apex

This repo holds **all of the Apex code** that powers the Transaction Security Policies (TSPs) in the **TSP Accelerator** library. If you’re using the TSP Accelerator app and want to tweak how a policy behaves—or build on top of it—this is the place.

## What’s in here

The `force-app/main/default/classes/` folder contains the Apex handlers that run when events fire (logins, API calls, report exports, list views, etc.).

Each policy has its own class (and tests), so you can change conditions, thresholds, or behavior without touching the rest of the app.

## Customizing policies

Now that you have the source, you can clone to:

- Adjust thresholds or criteria
- Add or relax allowlists and checks
- Extend or replace logic 

As a reminder - always test in a sandbox or scratch org first—these policies run in real time and can affect logins and API access.

## Need the full picture?

For setup, deployment, authentication, and how to use the TSP Accelerator app itself, see the listing on the [AppExchange](https://appexchange.salesforce.com/appxListingDetail?listingId=b5e1fa52-8a6d-4a7f-b787-88b0ede9e524).

---

*TL;DR: Apex behind the TSP Accelerator policies—use it to customize and extend.*
