# Validation and limitations

## Evidence available

The original German control build was reported working by the device operator.
Before that, the read-only diagnostic image displayed actual counters on the
printer and accepted its authenticated POST form. This demonstrated the
flash-resident payload, renderer callback and request ABI on that one device.
No serial number, private IP address, password, device dump or upload report is
included here. The English rebuild changes UI strings and the project layout;
it has not been separately flashed during repository preparation.

The source includes firmware-independent unit tests, C parser/model tests and
an emulator for the compiled control payload. Emulation provides mocked native
calls, devices, storage, resource locks and ADC input. Its simulated persistence
case reloads stored values into a new emulated instance. It does not boot the
original Brother firmware or exercise a real EEPROM driver.

The existing emulator covers all colors, near-to-full calibration, stale forms,
permissions/origin checks, busy guards, write/read-back faults, rollback failure,
pending usage races, dispatch-disable failures, preserved foreign guards and
latch freezing. Each new port needs equivalent tests against its own compiled
payload and device bindings.

## Still requires device testing

- Correct EEPROM programming/durability after a real restart.
- Full normal-to-near and near-to-full native state transitions over time.
- Interaction with maintenance, cancellation, printing and cartridge faults.
- Recovery from interrupted transfers and power loss.

No claim of universal compatibility, independent hardware certification, or
power-loss atomicity is made. Keep source identity, build manifest and operator
observations separate. A transport completion report is not a flash read-back.
