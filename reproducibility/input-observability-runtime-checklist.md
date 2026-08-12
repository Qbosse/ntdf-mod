# Stage-1 Input Observability Runtime Checklist

This checklist is for a separately authorized future runtime test. This build is
read-only: X, Square, Circle, and the diagnostic latch cannot invoke the
Stage-1 pointer write or restoration path.

1. Use only after a separate controlled installation authorization and after
   PCSX2 is fully closed before installation.
2. Boot, load Save B, open the hack menu, and select the existing Options entry.
3. Record the initial `I:` and `L:` values.
4. Press physical X once, wait for the next frame, and record `I:` and `L:`.
5. Press physical Square once, wait for the next frame, and record `I:` and `L:`.
6. Press physical Circle once, wait for the next frame, and record `I:` and `L:`.
7. Press physical Triangle once. It preserves the normal back action after
   latching the raw input. Re-enter Options and record `L:`.
8. Do not save. Exit PCSX2, restore the normal PNACH, and record the normal
   hash before any later experiment.

If anything unexpected occurs, do not save; exit PCSX2, restore the normal
PNACH, verify its hash, and record the observation. Stage 1 and Stage 2 remain
closed during this diagnostic.
