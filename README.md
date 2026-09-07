# Lab-Brain

Daily cash management and management reporting app for NMDC.

## Data safety
- Records are stored in Supabase Postgres, not Render's local filesystem.
- Before every normal data save, Lab-Brain keeps an automatic snapshot of the previous main data state (up to 30 snapshots).
- Admin can download a complete JSON backup from Reports → Data Safety & Demo.
- Admin can view automatic backup history and restore a previous snapshot. The current state is snapshotted before restore.
- Demo data (for report testing) is explicitly tracked and can be removed without targeting real records.

## Reports
- Revenue, Cash Counter Expenses, Patient Count cards.
- Daily analysis and completed-month trends.
- Excel-compatible CSV export for the selected report filters.
- PDF / Print uses the browser print dialog; choose "Save as PDF".

## Demo data (for report testing)
Admin → Reports → Data Safety & Demo → Load Demo Data.
The demo set uses the current month, days 1–7 when available, and is separately tracked. Use Remove Demo Data to remove only that set.
