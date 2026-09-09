# Lab-Brain V36

V26 is based on V25 and preserves the existing configuration model and business features.

## Included fixes
- Ameen bookings are not revenue; pending Ameen reduces Expected Cash.
- Ameen receipts increase the receiving user's current-day Expected Cash and do not create new revenue.
- Partial Ameen payments reduce the remaining pending balance and keep the due in the pending list until fully cleared.
- Ameen booking cash impact is scoped to the original booking user's portfolio; another user's cash is not reduced by that booking.
- Ameen pending lookup remains location-wide so another user can receive an existing due.
- Management can remove Ameen bookings/receipts without the Staff date restriction.
- Reports use Ameen pending balance rather than gross Ameen booking amount for Expected Cash.
- Added working Management Individual Entry Manager for deleting transactional records.
- Added no-cache headers for the deployed HTML to reduce stale-browser frontend issues.

## One-time deployment cleanup
On the first boot of V26, transactional records are cleared once while configuration is preserved. The cleanup affects:
- normal income/expense entries
- online entries and legacy online amounts
- manual refund entries and legacy refund amounts
- Ameen bookings/receipts
- patient counts
- handovers
- demo-data tracking

It does NOT clear:
- users/accounts/roles
- locations
- categories
- employees
- vendors
- doctors
- custom lists

A database migration flag prevents the cleanup from repeating on normal restarts.


## V28 performance and save reliability
- Normal entries remain silent after a successful save; the UI updates only after the server confirms the durable Postgres write.
- Entry-save failures show a specific "Not saved" indication.
- Cash handover shows a green "Saved ✓" confirmation after the durable save is confirmed.
- The Postgres persistence path was optimized to perform the main write and pre-change safety snapshot in one database round-trip; backup trimming is deferred/occasional and never blocks the confirmed main write.
- No card layout, settings model, category/location model, or existing business functionality was intentionally changed.


## V34 developments
- My Entries now shows the selected linked-list person/item under the Category (for example, Advance — employee name or Vendor — vendor name), while Who / Vendor continues to identify who entered the record.
- Print Summary now places Daily Summary and Cash Handover side-by-side, followed by My Entries, with compact print styling intended to fit a single A4 page and remain suitable for A3 printing.
- Management Reports no longer show Staff Performance or Cash Mismatch/Handover history by default; both are available as optional detailed reports with a selectable From/To date range.
- Individual Entry Management now uses Location-wise and Category-wise filters before displaying entries.


## V36 bug fixes
- Admin-selected Staff patient counts can now be viewed and corrected when a specific Staff user is selected; the Patient Count control remains intentionally unavailable when All users is selected because there is no single count to edit.
- Patient count retrieval tolerates legacy/case-variant username keys.
- Monthly trend bars now preserve proportional heights instead of flex-shrinking to nearly equal heights when values differ.
- Admin correction authority remains based on the logged-in Admin role, not the selected Staff account.


## V36 Changes
- Report chart value labels are rendered inside the chart bars/plot area.
- Revenue chart labels use compact K notation (e.g. 200K, 301.5K); expense labels retain full Rs values; patient labels retain whole-number counts.
- Normal entry, Online, Manual Refund, Ameen Booking, and Patient Count UI updates are optimistic for immediate feedback, with confirmed server persistence and rollback/error feedback if the durable save fails.
- Cash handover shows the green Saved ✓ confirmation after a confirmed save.
