# Security Specification: Luxe Admin Dashboard

## Data Invariants
1. A user document must match the UID of the authenticated user during creation.
2. Only admins can read all user documents and activity logs.
3. Users can read and update their own profile (limited fields).
4. System analytics are readable by admins, but only system processes (mocked via rules logic or admin bypass) can write them.
5. `role` field can only be updated by existing admins.

## The Dirty Dozen Payloads

1. **Identity Spoofing**: Attempt to create a user doc with a different UID.
2. **Privilege Escalation**: Attempt to set `role: 'admin'` during self-registration.
3. **Ghost Field Injection**: Adding `isVerified: true` to a profile update.
4. **Foreign Profile Read**: User A trying to `get` User B's document.
5. **Collection Scraping**: Authenticated user trying to `list` all users.
6. **Activity Log Tampering**: User trying to delete or edit an activity log entry.
7. **Analytics Manipulation**: User trying to reset `onlineUsers` count.
8. **Invalid ID Poisoning**: Using a 2KB string as a document ID.
9. **Role Modification**: User A trying to change their own role to admin in an `update`.
10. **Admin Spoofing**: Trying to write into the `admins/` collection.
11. **Timestamp Forgery**: Providing a client-side `updatedAt` that isn't `request.time`.
12. **PII Leak**: Non-admin user trying to list users to get all emails.

## Test Strategy
I will implement `firestore.rules` that block these by default.
1. `match /{document=**} { allow read, write: if false; }`
2. `isValidUser()` checks keys, types, and values.
3. `isAdmin()` check via `exists(/databases/$(database)/documents/admins/$(request.auth.uid))`
4. `affectedKeys().hasOnly()` for updates.
