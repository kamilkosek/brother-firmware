# Porting to another Brother model with an LLM

This repository is a worked example for one exact firmware revision. A port is
a new reverse-engineering project. Keep the working MFC-J5720DW target intact
and create a separate profile, native binding module and test fixtures.
The present tools have one pinned target; adding a JSON profile alone does not
select a new model or update the Python guards and C addresses.

## What to give the LLM

Supply the exact model, cartridge family, current reported firmware/SPEC, the
original update image and its SHA-256, your observed failure, and the actions
you authorize. Keep credentials, serial numbers, captures and full firmware
images in private ignored directories. Establish who will perform uploads.

Provide the current source tree, [architecture](architecture.md),
[container notes](firmware-format.md) and [validation scope](validation.md).
An LLM with local shell access and native disassembly/decompilation tools is
useful. Ghidra or a comparable engine can analyze the image; REA was used during
the original investigation but is not a runtime/build dependency.

## Investigation stages

### 1. Identify and preserve the target

Query the printer read-only, record model/SPEC/firmware and hash the original
image. Keep an untouched copy. Determine the real update format and recovery
method for that hardware. Record uncertainty when recovery is unproven.

```sh
python tools/firmware_download.py --printer PRINTER_ADDRESS --query-only
sha256sum /path/to/original-update
```

The downloader's vendor endpoint and the extractor's LZ5014 layout are observed
implementations, not universal Brother interfaces. Use a different extractor
when the target container requires one. A failed exact-source guard is a reason
to investigate the new target, not a reason to remove the guard.

### 2. Establish architecture and container invariants

Verify CPU family, code/data byte order, ARM versus Thumb state, entry points,
load addresses, RO/RW/ZI boundaries, flash maps and unused payload space. Check
framing, compression, signatures, checksums and model-code validation.

Rebuild an unmodified image byte-for-byte where possible before adding changes.
A new update mechanism must be demonstrated separately. Do not assume this
model's legacy prefix avoids the signature checks on another device.

### 3. Trace real ink data from display to storage

Start at the native web bars/status object and trace the exact producer. Find
persistent and RAM counters, color order, units, field widths, fractional/pending
usage, thresholds, history-dependent baselines, optical sensor state, cartridge
presence and empty/fault gates. Trace readers and writers independently.

For every binding, keep a table with address, instruction mode, recovered ABI,
callers, input/output buffers, side effects, persistence and evidence source.
Label observations, inferences and unknowns. Keep the full local evidence
outside the public source tree, with a sanitized summary in the port's docs.

The original port found two distinct branches: total consumption before low ink
and a sensor-since-low counter afterwards. A linear UI override would not have
provided coherent native calibration. Re-derive this relationship on your target.

### 4. Prove a read-only integration first

Find the web route, actual GET/POST callback path, native authentication and body
reader. Build a small authenticated panel that reads real counters and validates
inputs but binds no persistent write operation. Test missing login, method,
Origin, duplicate fields and oversized encodings in an emulator.

Have the operator upload that diagnostic image and verify the panel, native
values and POST path on hardware. Hardware evidence is a separate checkpoint
from a successful compile or package checksum.

### 5. Design a coherent writer

Derive the native inverse percentage mapping and its representable ranges.
Handle the native normal/near transition intentionally, including restoration
at boot. Preserve raw sensor diagnostics and keep cartridge/fault gates explicit.
Do not borrow undocumented storage bits or silently erase unrelated state.

Establish native resource exclusion that actually prevents printing or relevant
maintenance during a commit. An object mutex alone did not prove this in the
original port. Verify return values, owner namespaces, nesting behavior and
cleanup on every failure path. Keep blocking IO outside bounded dispatch/IRQ
critical sections.

Write one selected color, compare the prior counter to reject stale requests,
read back the stored values, publish coherent RAM/pending state and check the
original percentage getter. Snapshot enough state to attempt restoration and
report restoration failure distinctly. Document power-loss limitations.

### 6. Port packaging and guards

Add a new exact-source hash, expected original hook bytes, model/SPEC checks,
flash bounds and installed-version guard. Update all absolute addresses in
native C bindings, not just `profile.json`. Derive any veneer's alignment, PC
literal position and branch range for the new instruction set.

Keep the build offline and the upload explicit. Re-extract the whole new package
and compare code/data sections intended to remain unchanged. Reject unexpected
architecture, writable payload state and unresolved symbols.

### 7. Test the actual compiled payload

Use host tests for parsing/mathematics, then execute the compiled payload against
mocked native APIs. Test all colors and state transitions, malformed requests,
unauthorized access, busy/stale guards, failures at every write/read-back step,
rollback, pending consumption, concurrent state changes and reboot restoration.
An emulator does not establish real driver behavior or hardware persistence.

### 8. Let the operator validate on hardware

Record the exact image hash and expected version. After an explicit operator
upload, verify the live version, panel, one selected cartridge, native bar,
untouched other colors, delayed refresh, reboot retention and subsequent printed
consumption. Broaden testing only after these checks pass. Publish precise
results rather than declaring an untested port compatible.

## Reusable LLM prompt

```text
I own a Brother [MODEL] using [CARTRIDGE FAMILY]. It reports [FIRMWARE], SPEC
[SPEC]. The original update SHA-256 is [HASH]. My observed issue is [SYMPTOM].
I want real per-color consumption-counter calibration through the native web UI.

Use this repository as a reference, not as an address map for my device.
First inventory the image and prove architecture, framing, signatures and
recovery/update constraints. Trace the native display to persistent/RAM ink
state and the real write/reset paths. Keep an evidence table with recovered
ABIs, side effects and unresolved questions. Do not invent function semantics.

Build and test a read-only authenticated diagnostic integration before binding
writes. For the writer, derive the native percentage inverse, native resource
exclusion, state transitions, pending consumption and restart behavior. Keep
all exact-source/hook/model guards. Add a separate profile and binding module.

Use offline tests and compiled-payload emulation. Separate static, simulated
and hardware evidence. Preserve private originals/logs outside the public tree.
Do not send firmware, print jobs, persistent writes or updates to my printer
until I explicitly authorize that particular hardware test. I will perform
uploads myself unless I later say otherwise.

Report concrete artifacts, their hashes, verification results, limitations and
the smallest next hardware test. Never claim a checksum or successful transport
proves execution or EEPROM persistence on the device.
```

## Useful port deliverables

A minimal target profile and source binding map; exact-source and byte guards;
a reproducible offline builder; parser/model/transaction tests; an emulator with
an allowlist of native calls; a diagnostic-first image; an explicit uploader;
and a sanitized validation record distinguishing tested and untested behavior.
