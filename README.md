# Lab-Brain

## V25

V25 is based on V24 and preserves the existing application structure and Supabase `app_state` data model.

### Ameen accounting and workflow
- Ameen Booking / Due is **not included in Total Revenue**.
- On the booking date, the booking amount is deducted from Expected Cash because no physical cash was received.
- Ameen Receipt is a separate cash-receipt action and is not new revenue.
- Ameen receipts are linked to an existing pending due.
- Partial payments are supported; only the remaining balance stays pending.
- Ameen cash impact is portfolio/user-specific: a booking affects the booking user's cash calculation; a later receipt affects the user who physically receives it.
- Ameen receipt removal is supported under the normal date/ownership rules and restores the linked due balance.

### Other preserved behavior
- Admin/Reviewer management access and Admin settings remain.
- Staff previous-date correction window remains 00:00–00:30 Pakistan time.
- Admin is not date/time restricted for entry add/remove.
- Online and Manual Refund remain individual persistent entries.
- Existing category/location/custom-list functionality is preserved.
- Existing Supabase data is not reset by the application update.
