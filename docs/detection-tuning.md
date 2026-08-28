# Detection Tuning

The detections were validated against normal endpoint activity before being finalized.

Broad searches were reviewed for expected Windows and application behavior. Noisy patterns were narrowed where necessary so that alerts focus on activity more relevant to analyst triage.

Examples include restricting Rundll32 activity to user-writable paths and combining Run Key persistence with a user-writable payload location.

The final rules prioritize useful investigative context over maximum event volume.